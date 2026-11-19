#!/usr/bin/env python3
"""
egress_score.py — egress-observatory 评分逻辑的 Python 复刻（只读调研用）。

来源：https://blackslience-reaper.github.io/egress-observatory/
复刻依据（2026-11-19 下载的部署版本）：
  src/score.js（评分纯函数）、src/sources.js（来源适配）、src/asn.js（ASN 画像）、
  src/blocklists.js（DNSBL + CIDR 列表）、src/main.js（证据组装）、
  src/supplements.js（IPOK 补充）、src/page-lookups.js（网页补充）。

用法：
  python3 egress_score.py 1.2.3.4            # 人类可读报告
  python3 egress_score.py --json 1.2.3.4     # JSON 输出
  python3 egress_score.py --batch ips.txt    # 批量（每行一个 IP），输出对照表

评分公式（score.js 原文）：Score = 92 + bonuses(≤10) − Σ min(分类上限, Σ 扣分项)，
Tor 出口封顶 25 分。等级：S ≥95，A ≥85，B ≥70，C ≥55，D ≥40，F <40。
分类上限：匿名化 50、滥用与黑名单 40、邻居与 ASN 信誉 25、网络类型与 ASN 画像 20、
原生与定位 8、连接实测 50（仅自查时适用，本脚本不查远端 IP 的实测项）。

与页面版的已知偏差（见文件末尾 NOTES）：
  1. 网页补充（IPSuper / IPinfo 网页 / Chrome 插件）未复刻——页面服务当前不可用
     （/v1/page/* 返回 page-service-unavailable），浏览器实测时是否拿到补充数据未知。
  2. 未调 /v1/seen（避免自动化脚本刷高该站的共享计数；影响极小）。
  3. 未做连接实测（WebRTC/DNS/验证码等仅对“本机出口”有意义）。
  4. 场景分（流媒体/AI/验证码等）与 verdict 未复刻（展示用，不影响总分）。

只用 Python 标准库。CIDR 列表缓存于 ~/.cache/egress-score/（12 小时有效）。
本机 VM 出站经代理，部分上游结论需在 GCP 上复核（见 NOTES）。
"""
import argparse
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://egress-observatory-api.reaper-f.chatgpt.site"
CACHE_DIR = os.path.expanduser("~/.cache/egress-score")
UA = {"User-Agent": "egress-score/1.0 (research replica; +https://github.com/BlackSlience-Reaper/egress-observatory)"}
WORKER_MIN_INTERVAL = 2.2  # worker API 限频 30 次/分钟，留余量

# ---------------- JS 语义小工具 ----------------

def js_round(x):
    """JS Math.round：.5 向 +∞ 取整（Python round 是银行家舍入）。"""
    return math.floor(x + 0.5)

def r1(v):
    return js_round(v * 10) / 10

def r3(v):
    return js_round(v * 1000) / 1000

def clamp(v, lo, hi):
    return min(hi, max(lo, v))

def num(v):
    try:
        if v is None or isinstance(v, bool):
            return None
        f = float(v)
        return f if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None

def text(v):
    if v is None:
        return None
    s = str(v).strip()
    return s or None

def bool_(v):
    return v if isinstance(v, bool) else None

def country_code(v):
    s = text(v)
    if s and re.fullmatch(r"[A-Za-z]{2}", s):
        return s.upper()
    return None

def asn_number(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    m = re.search(r"(\d+)", str(v))
    return int(m.group(1)) if m else None

def pct(v):
    return f"{round(v * 100)}%"

# ---------------- 常量（score.js / asn.js 原文） ----------------

BASE = 92
BONUS_CAP = 10
UNSURE = 0.6
ASN_RELIEF = 0.2

CATEGORIES = [
    {"id": "anon", "label": "匿名化", "cap": 50},
    {"id": "abuse", "label": "滥用与黑名单", "cap": 40},
    {"id": "neighbours", "label": "邻居与 ASN 信誉", "cap": 25},
    {"id": "network", "label": "网络类型与 ASN 画像", "cap": 20},
    {"id": "geo", "label": "原生与定位", "cap": 8},
    {"id": "live", "label": "连接实测", "cap": 50},
]

SOURCE_WEIGHTS = {
    "ipinfo": {"flags": 1.3, "type": 1.3, "geo": 1.6},
    "proxycheck": {"flags": 1.0, "type": 1.0, "risk": 1.0},
    "ipapiis": {"flags": 0.9, "type": 0.9, "risk": 0.8},
    "ipapi": {"flags": 0.8, "type": 0.8},
    "ipquery": {"flags": 0.8, "risk": 0.5},
    "ip2location": {"flags": 0.6},
    "blackbox": {"flags": 0.5, "type": 0.5},
    "freeipapi": {"flags": 0.4},
    "shodan": {"flags": 0.5, "positiveOnly": True, "observed": True},
    "sfs": {"flags": 0.8, "positiveOnly": True, "observed": True},
    "iplocate": {"flags": 0.9, "type": 0.8},
    "geoiplookup": {"type": 0.7},
    "ipapimirror": {"flags": 0.5, "type": 0.5, "geo": 0.6},
    "netatlas": {"geo": 0.6},
    "otx": {"flags": 0.6, "positiveOnly": True, "observed": True},
    "greynoise": {"flags": 0.8, "observed": True},
    "crowdsec": {"flags": 0.9, "risk": 1.0, "observed": True},
    "vpnapi": {"flags": 0.8},
    "iphub": {"flags": 0.7, "type": 0.7},
    "getipintel": {"flags": 0.5, "risk": 0.5},
    "scamalytics": {"flags": 0.8, "risk": 1.1},
    "virustotal": {"flags": 0.8, "risk": 0.8, "observed": True},
    "onionoo": {"flags": 1.0},
    "abuseipdb": {"flags": 1.0, "type": 0.9, "risk": 1.2},
    "ipqs": {"flags": 1.0, "type": 0.9, "risk": 0.7},
    "ipregistry": {"flags": 0.9, "type": 0.9},
    "ipdata": {"flags": 0.8, "type": 0.8, "risk": 0.8},
    "ptr": {"flags": 0.5, "type": 0.5},
}

GEO_FAMILY = {
    "abuseipdb": "ipinfo",
    "ipsb": "maxmind", "ipleak": "maxmind", "maxmind": "maxmind", "geojs": "maxmind",
    "dbip": "dbip", "freeipapi": "dbip", "netatlas": "dbip", "ipapi": "ipapi", "ipapimirror": "ipapi",
}

TYPE_LABEL = {"residential": "家宽", "mobile": "移动网络", "business": "商业宽带", "hosting": "机房", "education": "教育网"}

# ASN 已知名单（asn.js 原文）
_ASN_LISTS = {
    "hosting": [16509, 14618, 8987, 396982, 19527, 8075, 8068, 8069, 12076, 31898, 36351, 45102, 37963, 132203, 45090, 136907, 55990, 135377, 59019,
                14061, 63949, 20473, 16276, 24940, 213230, 51167, 40021, 12876, 60781, 28753, 30633, 59253, 7203, 395954, 9009, 60068, 212238, 40676, 8100,
                36352, 53667, 25820, 906, 199524, 202422, 36007, 63473, 35916, 62240, 21859, 54600, 35908, 46844, 54290, 47583, 8560, 6724, 31034, 202053,
                54825, 3258, 35913, 397423, 62904, 46606, 26496, 32244, 22612, 19318, 32613, 13213, 29802, 33387, 138997, 141995, 55933,
                20278, 397373, 49505, 207990, 44477, 203020, 210644, 50673, 48282, 58061, 211252, 31173, 39351, 9370, 2635, 7506, 38001],
    "cdn": [13335, 209242, 20940, 16625, 54113, 22822, 33438, 15169, 32934, 2906, 16550, 60626],
    "transit": [174, 3356, 3549, 1299, 2914, 6453, 6762, 3257, 6939, 4637, 3491, 1239, 6461, 5511, 9002, 4826, 58453, 4809, 23764, 10099, 9929,
                12956, 1273, 2828, 10026, 20485, 7473, 5400, 4651, 9304, 37100, 64049],
    "mobile": [9605, 21928, 22394, 6167, 20057, 55836, 31133, 16135, 45609, 24445, 56040, 56041, 56042, 56044, 56046, 56047, 56048],
    "isp": [4134, 4837, 9808, 4812, 17621, 4808, 17816, 7922, 7018, 701, 209, 20115, 22773, 5650, 11427, 20001, 10796, 11351, 12271, 33363, 6128,
            3209, 5089, 2856, 3215, 12322, 5410, 15557, 3352, 3269, 1136, 2516, 4713, 17676, 2527, 4766, 9318, 3786, 3462, 4780, 9924, 4760, 9269,
            10091, 9506, 45899, 7552, 18403, 17974, 9829, 24560, 1221, 4804, 7545, 812, 577, 6327, 852, 8151, 28573, 12389, 8402, 25513, 9121, 8452,
            6849, 5617, 12741, 2119, 3301, 1759, 5432, 6805, 8881, 3303, 8447, 15502, 2860, 3243, 12430, 6739, 30722, 12874, 4788, 9583, 23969, 4818,
            17552, 131090, 18881, 26599, 27699, 7303, 10318, 22927, 13999, 4230, 6830, 3320, 7713],
}
KNOWN_ASN = {asn: cls for cls, lst in _ASN_LISTS.items() for asn in lst}
TRANSIT_HOSTING = {6939, 58453, 4809, 23764, 10099, 9929, 3491}

KEYWORDS = [
    ("cdn", re.compile(r"\b(cdn|akamai|cloudflare|fastly|edgecast|limelight|stackpath|bunnycdn|bunnyway|content delivery)\b", re.I), 1.5),
    ("hosting", re.compile(r"(hosting|\bhost\b|server|datacent(er|re)|data cent(er|re)|\bidc\b|cloud|\bvps\b|colo(cation)?|dedicated|compute|virtual|\bovh|hetzner|leaseweb|contabo|digitalocean|linode|vultr|choopa|amazon|\baws\b|azure|alibaba|aliyun|tencent|oracle|softlayer|rackspace|\bm247|datacamp|cdn77|psychz|quadranet|colocrossing|frantech|buyvm|krypt|sharktech|hostwinds|ionos|scaleway|upcloud|kamatera|g-?core|zenlayer|clouvider|dmit|xtom|racknerd|hostinger|\bvpn\b|proxy|\bnetwork solutions\b)", re.I), 1.4),
    ("transit", re.compile(r"(backbone|transit|\bcarrier\b|cogent|lumen|level ?3|arelion|telia carrier|\bgtt\b|zayo|tata comm|sparkle|pccw global|telstra global|telstra international|hurricane electric|ntt (america|global)|global crossing|\bretn\b)", re.I), 1.6),
    ("mobile", re.compile(r"(mobile|wireless|cellular|\blte\b|\b5g\b|\bgsm\b|mobil\b|movil|móvil)", re.I), 1.2),
    ("education", re.compile(r"(universit|college|school|academ|education|research|\bedu\b|cernet|institute|\bnren\b)", re.I), 1.6),
    ("government", re.compile(r"(government|ministry|\bgov\b|federal|municipal)", re.I), 1.4),
    ("isp", re.compile(r"(telecom|telekom|telecommunication|broadband|\bcable|communications?|comcast|charter|verizon|at&t|\bisp\b|internet service|\bdsl\b|fib(er|re)|ftth|netcom|unicom|telefonica|vodafone|orange|kddi|\bntt\b|softbank|telstra|optus|rogers|\bbell\b|shaw|telus|hinet|chunghwa|pccw|hkbn|singtel|starhub|telkom|viettel|vnpt|airtel|\bjio\b|rostelecom|beeline|megafon|\bmts\b|turk ?telekom|kt corp|sk broadband|lg ?u\+|chinanet|china telecom|china mobile|cmnet)", re.I), 1.0),
]

PDB_TYPES = {
    "Cable/DSL/ISP": ("isp", 2.2), "NSP": ("transit", 2.2), "Content": ("hosting", 1.8), "Enterprise": ("business", 1.6),
    "Educational/Research": ("education", 2.2), "Non-Profit": ("business", 1.0), "Government": ("government", 2.0),
    "Route Server": ("business", 0.6), "Network Services": ("business", 0.6), "Route Collector": ("business", 0.6),
}

CLASS_LABEL = {
    "isp": "运营商宽带", "mobile": "移动运营商", "hosting": "机房 / 云", "cdn": "CDN / 内容网络", "transit": "骨干 / 传输网",
    "business": "企业网络", "education": "教育科研网", "government": "政府网络",
}

# ---------------- HTTP ----------------

_worker_lock = threading.Lock()
_worker_last = [0.0]

def _pace_worker():
    with _worker_lock:
        wait = WORKER_MIN_INTERVAL - (time.time() - _worker_last[0])
        if wait > 0:
            time.sleep(wait)
        _worker_last[0] = time.time()

def fetch(url, timeout=20, headers=None, as_text=False, pace=False):
    """返回 (ok, data_or_error, status)。data 为解析后的 JSON 或文本。"""
    if pace:
        _pace_worker()
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if as_text:
                return True, raw.decode("utf-8", "replace"), resp.status
            try:
                return True, json.loads(raw.decode("utf-8", "replace")), resp.status
            except json.JSONDecodeError:
                return False, "非 JSON 响应", resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
            try:
                return False, json.loads(body), e.code
            except json.JSONDecodeError:
                return False, body[:200], e.code
        except Exception:
            return False, f"HTTP {e.code}", e.code
    except Exception as e:
        return False, str(e)[:200], None

def get_json(url, timeout=20, headers=None, pace=False):
    ok, data, status = fetch(url, timeout, headers, pace=pace)
    return {"ok": ok, "data": data if ok else None, "error": None if ok else data, "status": status}

# ---------------- IP 工具 ----------------

def parse_ip(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None

def reverse_name(ip):
    addr = parse_ip(ip)
    if addr is None:
        return None
    if addr.version == 4:
        return ".".join(reversed(str(addr).split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))

def ip_int(ip):
    addr = parse_ip(ip)
    return int(addr) if addr is not None else None

def int_to_ip(n):
    return str(ipaddress.IPv4Address(n))

# ---------------- 来源适配（sources.js 移植） ----------------

def flags_of(values=None):
    base = {"vpn": None, "proxy": None, "tor": None, "hosting": None, "relay": None,
            "abuser": None, "crawler": None, "mobile": None, "bogon": None}
    if values:
        for k, v in values.items():
            if k in base:
                base[k] = bool_(v)
    return base

def same_ip(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b

EXTRA_KEYS = ["noise", "riot", "classification", "name", "reputation", "behaviors", "block", "probability",
              "riskLabel", "vtMalicious", "vtSuspicious", "vtReputation", "asnType", "resProxy", "satellite",
              "anycast", "privacyService", "activeVpn", "activeTor", "abuseVelocity", "connectionType",
              "reports", "lastReported"]

def worker_record(data, ip):
    """worker 路由返回的统一归一化（sources.js workerRecord）。"""
    if not data or data.get("status") != "success":
        raise ValueError((data or {}).get("error") or "服务端未返回结果")
    if data.get("ip") and not same_ip(data["ip"], ip):
        raise ValueError("返回目标与查询 IP 不一致")
    usage = data.get("usageType")
    network = data.get("networkType")
    type_ = (usage or network) if (usage or network) in ("residential", "isp", "mobile", "business", "hosting", "education") else None
    if usage in ("residential", "mobile", "business", "hosting", "education", "government"):
        usage_type = usage
    else:
        usage_type = {"isp": "residential", "residential": "residential", "mobile": "mobile",
                      "business": "business", "hosting": "hosting", "education": "education"}.get(network)
    company = data.get("companyType")
    out = {
        "country": country_code(data.get("country")), "city": text(data.get("city")),
        "region": text(data.get("region")), "lat": num(data.get("lat")), "lon": num(data.get("lon")),
        "asn": asn_number(data.get("asn")), "org": text(data.get("org")), "tz": text(data.get("timezone")),
        "type": type_, "usageType": usage_type,
        "companyType": company if company in ("residential", "isp", "mobile", "business", "hosting", "education", "government") else None,
        "flags": flags_of(data.get("flags") or {}),
        "risk": num(data.get("risk")), "hostname": text(data.get("hostname")),
    }
    if data.get("devices"):
        out["devices"] = {"address": num(data["devices"].get("address")), "subnet": num(data["devices"].get("subnet"))}
    if data.get("lastSeen"):
        out["lastSeen"] = text(data["lastSeen"])
    for key in EXTRA_KEYS:
        v = data.get(key)
        if isinstance(v, str):
            out[key] = text(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v):
            out[key] = v
        elif isinstance(v, bool):
            out[key] = v
        elif isinstance(v, list):
            out[key] = [text(str(x)) for x in v if text(str(x))][:6]
    return out

class SourceFail(Exception):
    pass

def worker_route(route, ip, health):
    if not health or route not in (health.get("routes") or []):
        raise SourceFail("服务端未启用此来源")
    r = get_json(f"{API_BASE}/v1/{route}?ip={urllib.parse.quote(ip)}", timeout=15, pace=True)
    if not r["ok"]:
        err = r["error"]
        msg = err.get("error") if isinstance(err, dict) else str(err)
        raise SourceFail(msg or "请求失败")
    try:
        return worker_record(r["data"], ip)
    except ValueError as e:
        raise SourceFail(str(e))

def src_proxycheck(ip, ctx):
    return worker_route("proxycheck", ip, ctx["health"])

def src_ipapi(ip, ctx):
    return worker_route("ipapi", ip, ctx["health"])

def src_ip2location(ip, ctx):
    return worker_route("ip2location", ip, ctx["health"])

def src_dbip(ip, ctx):
    return worker_route("dbip", ip, ctx["health"])

def src_abuseipdb(ip, ctx):
    rec = worker_route("abuseipdb", ip, ctx["health"])
    rec["type"] = rec.get("usageType")
    return rec

def src_getipintel(ip, ctx):
    try:
        return worker_route("getipintel", ip, ctx["health"])
    except SourceFail:
        # 页面回退：/v1/page/getipintel（当前服务常不可用，失败即放弃）
        r = get_json(f"{API_BASE}/v1/page/getipintel?ip={urllib.parse.quote(ip)}", timeout=60, pace=True)
        if not r["ok"]:
            raise SourceFail("GetIPIntel 不可用")
        d = r["data"] or {}
        if not same_ip(d.get("ip"), ip):
            raise SourceFail("返回目标不一致")
        p = num(d.get("probability"))
        if p is None or not (0 <= p <= 1):
            raise SourceFail(d.get("error") or "未返回概率")
        return {"flags": flags_of({"proxy": p >= 0.99, "vpn": p >= 0.99}),
                "risk": num(d.get("risk")), "probability": p, "geoVote": False}

def src_ipquery(ip, ctx):
    r = get_json(f"https://api.ipquery.io/{urllib.parse.quote(ip)}?format=json", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    loc, isp, risk = d.get("location") or {}, d.get("isp") or {}, d.get("risk") or {}
    return {
        "country": country_code(loc.get("country_code")), "region": text(loc.get("state")),
        "city": text(loc.get("city")), "lat": num(loc.get("latitude")), "lon": num(loc.get("longitude")),
        "tz": text(loc.get("timezone")), "asn": asn_number(isp.get("asn")),
        "org": text(isp.get("org")) or text(isp.get("isp")),
        "flags": flags_of({"vpn": risk.get("is_vpn"), "proxy": risk.get("is_proxy"), "tor": risk.get("is_tor"),
                           "hosting": risk.get("is_datacenter"), "mobile": risk.get("is_mobile")}),
        "type": "mobile" if risk.get("is_mobile") is True else None,
        "usageType": "hosting" if risk.get("is_datacenter") is True else ("mobile" if risk.get("is_mobile") is True else None),
        "risk": num(risk.get("risk_score")),
    }

_RISK_LABEL = {"very low": 3, "low": 10, "elevated": 40, "high": 70, "very high": 90}

def src_ipapiis(ip, ctx):
    health = ctx["health"]
    if health and "ipapiis" in (health.get("routes") or []):
        return worker_route("ipapiis", ip, health)
    r = get_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("error"):
        raise SourceFail(text(d["error"]) or "拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    company = d.get("company") if isinstance(d.get("company"), dict) else {}
    asn = d.get("asn") if isinstance(d.get("asn"), dict) else {}
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    m = re.search(r"\(([^)]+)\)", str(company.get("abuser_score") or ""))
    type_map = {"isp": "isp", "hosting": "hosting", "business": "business", "education": "education",
                "government": "business", "banking": "business"}
    return {
        "country": country_code(loc.get("country_code") or d.get("country")),
        "region": text(loc.get("state") or d.get("region")), "city": text(loc.get("city") or d.get("city")),
        "lat": num(loc.get("latitude") if loc.get("latitude") is not None else d.get("lat")),
        "lon": num(loc.get("longitude") if loc.get("longitude") is not None else d.get("lon")),
        "tz": text(loc.get("timezone") or d.get("timezone")),
        "asn": asn_number(asn.get("asn") if asn.get("asn") is not None else d.get("asn")),
        "org": text(company.get("name") or d.get("company")),
        "flags": flags_of({"bogon": d.get("is_bogon"), "mobile": d.get("is_mobile"), "crawler": d.get("is_crawler"),
                           "hosting": d.get("is_datacenter"), "tor": d.get("is_tor"), "proxy": d.get("is_proxy"),
                           "vpn": d.get("is_vpn"), "abuser": d.get("is_abuser")}),
        "type": type_map.get(company.get("type")),
        "risk": _RISK_LABEL.get((m.group(1) if m else "").lower()),
        "usageType": "hosting" if d.get("is_datacenter") is True else ("mobile" if d.get("is_mobile") is True else None),
        "companyType": {"isp": "residential", "hosting": "hosting", "business": "business",
                        "education": "education", "government": "government", "banking": "business"}.get(company.get("type")),
        "asnType": text(asn.get("type")), "companyDomain": text(company.get("domain")),
    }

def src_ipinfo(ip, ctx):
    health = ctx["health"]
    if health and "ipinfo" in (health.get("routes") or []):
        rec = worker_route("ipinfo", ip, health)
        return rec
    r = get_json(f"https://ipinfo.io/{urllib.parse.quote(ip)}/json", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    lat = lon = None
    if d.get("loc"):
        parts = str(d["loc"]).split(",")
        if len(parts) == 2:
            lat, lon = num(parts[0]), num(parts[1])
    org = text(d.get("org"))
    return {
        "country": country_code(d.get("country")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": lat, "lon": lon, "tz": text(d.get("timezone")), "asn": asn_number(d.get("org")),
        "org": re.sub(r"^AS\d+\s+", "", org, flags=re.I) if org else None,
        "hostname": text(d.get("hostname")), "flags": flags_of({"bogon": d.get("bogon")}),
        "anycast": d.get("anycast") is True,
    }

def src_ipwhois(ip, ctx):
    r = get_json(f"https://ipwho.is/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("success") is False:
        raise SourceFail(text(d.get("message")) or "拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    conn = d.get("connection") or {}
    tz = d.get("timezone") or {}
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(tz.get("id")),
        "asn": asn_number(conn.get("asn")), "org": text(conn.get("org")) or text(conn.get("isp")),
        "isp": text(conn.get("isp")), "domain": text(conn.get("domain")), "flags": flags_of(),
    }

def src_ipsb(ip, ctx):
    r = get_json(f"https://api.ip.sb/geoip/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("timezone")),
        "asn": asn_number(d.get("asn")), "org": text(d.get("isp")) or text(d.get("organization")), "flags": flags_of(),
    }

def src_ipleak(ip, ctx):
    r = get_json(f"https://ipleak.net/json/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region_name")), "city": text(d.get("city_name")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("time_zone")),
        "asn": asn_number(d.get("as_number")), "org": text(d.get("isp_name")),
        "regCountry": country_code(d.get("registered_country_code")),
        "hostname": text(d.get("reverse")), "prefix": text(d.get("as_network")), "flags": flags_of(),
    }

def src_geojs(ip, ctx):
    r = get_json(f"https://get.geojs.io/v1/ip/geo/{urllib.parse.quote(ip)}.json", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("timezone")),
        "asn": asn_number(d.get("asn")), "org": text(d.get("organization_name")), "flags": flags_of(),
    }

def src_ipapico(ip, ctx):
    r = get_json(f"https://ipapi.co/{urllib.parse.quote(ip)}/json/", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("error"):
        raise SourceFail(text(d.get("reason")) or "拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("timezone")),
        "asn": asn_number(d.get("asn")), "org": text(d.get("org")), "prefix": text(d.get("network")), "flags": flags_of(),
    }

def src_iplocation(ip, ctx):
    r = get_json(f"https://api.iplocation.net/?ip={urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if str(d.get("response_code")) != "200":
        raise SourceFail(text(d.get("response_message")) or "拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    return {"country": country_code(d.get("country_code2")), "org": text(d.get("isp")), "flags": flags_of()}

def src_freeipapi(ip, ctx):
    r = get_json(f"https://free.freeipapi.com/api/v1/json/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ipAddress") and not same_ip(d["ipAddress"], ip):
        raise SourceFail("返回目标不匹配")
    tzs = d.get("timeZones") or []
    return {
        "country": country_code(d.get("countryCode")), "region": text(d.get("regionName")), "city": text(d.get("cityName")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")),
        "tz": text(tzs[0]) if tzs else None, "asn": asn_number(d.get("asn")), "org": text(d.get("asnOrganization")),
        "flags": flags_of({"proxy": d.get("isProxy")}),
    }

RIPE = "https://stat.ripe.net/data"

def ripe_url(call, params):
    q = dict(params)
    q["sourceapp"] = "egress-observatory"
    return f"{RIPE}/{call}/data.json?{urllib.parse.urlencode(q)}"

def src_maxmind(ip, ctx):
    r = get_json(ripe_url("maxmind-geo-lite", {"resource": ip}), timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    loc = None
    try:
        loc = d["data"]["located_resources"][0]["locations"][0]
    except (KeyError, IndexError, TypeError):
        loc = None
    if not loc:
        raise SourceFail("无定位数据")
    return {"country": country_code(loc.get("country")), "city": text(loc.get("city")),
            "lat": num(loc.get("latitude")), "lon": num(loc.get("longitude")), "flags": flags_of()}

def src_iplocate(ip, ctx):
    r = get_json(f"https://www.iplocate.io/api/lookup/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("error"):
        raise SourceFail(text(d["error"]) or "拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    p = d.get("privacy") or {}
    asn = d.get("asn") or {}
    company = d.get("company") or {}
    comp = {"isp": "residential", "hosting": "hosting", "business": "business",
            "education": "education", "government": "government"}
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("subdivision")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("time_zone")),
        "asn": asn_number(asn.get("asn")), "org": text(company.get("name")) or text(asn.get("name")),
        "flags": flags_of({"vpn": p.get("is_vpn"), "proxy": p.get("is_proxy"), "tor": p.get("is_tor"),
                           "relay": p.get("is_icloud_relay"), "hosting": p.get("is_hosting"),
                           "abuser": p.get("is_abuser"), "bogon": p.get("is_bogon")}),
        "type": "hosting" if p.get("is_hosting") is True else None,
        "usageType": "hosting" if p.get("is_hosting") is True else None,
        "companyType": comp.get(company.get("type")), "asnType": text(asn.get("type")),
        "anycast": d.get("is_anycast") is True,
    }

def src_geoiplookup(ip, ctx):
    r = get_json(f"https://json.geoiplookup.io/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("success") is False:
        raise SourceFail("拒绝查询")
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    conn = str(d.get("connection_type") or "")
    if re.search(r"corporate|business", conn, re.I):
        usage = "business"
    elif re.search(r"cable|dsl|dialup|residential|fiber", conn, re.I):
        usage = "residential"
    elif re.search(r"cellular|mobile", conn, re.I):
        usage = "mobile"
    elif re.search(r"hosting|data ?cent", conn, re.I):
        usage = "hosting"
    else:
        usage = None
    return {
        "country": country_code(d.get("country_code")), "region": text(d.get("region")), "city": text(d.get("city")),
        "lat": num(d.get("latitude")), "lon": num(d.get("longitude")), "tz": text(d.get("timezone_name")),
        "asn": asn_number(d.get("asn_number")), "org": text(d.get("org")) or text(d.get("isp")),
        "hostname": text(d.get("hostname")), "type": usage, "usageType": usage, "flags": flags_of(),
    }

def src_blackbox(ip, ctx):
    r = get_json(f"https://blackbox.ipinfo.app/api/v3beta/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("error") or not d.get("ip") or not isinstance(d.get("signals"), dict):
        raise SourceFail("Beta 接口未返回可识别的目标与分类字段")
    if not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    sig = d["signals"]
    classification = text(d.get("classification"))
    has_class = classification in ("residential", "mobile", "business", "hosting", "vpn", "tor", "privacy_relay", "bogon")

    def detected(*values):
        vals = [v for v in values]
        if any(v is True for v in vals):
            return True
        if vals and all(v is False for v in vals):
            return False
        return None

    def classified_flag(v):
        if v is True:
            return True
        return bool_(v) if has_class else None

    usage = {"residential": "residential", "mobile": "mobile", "business": "business", "hosting": "hosting"}.get(classification)
    asn = d.get("asn") or {}
    prefix = None
    if asn.get("network") and isinstance(asn.get("cidr"), int):
        prefix = f"{asn['network']}/{asn['cidr']}"
    return {
        "asn": asn_number(asn.get("number")), "org": text(asn.get("name")),
        "hostname": text((d.get("rdns") or {}).get("hostname")), "prefix": prefix,
        "type": usage, "usageType": usage, "geoVote": False,
        "flags": flags_of({
            "proxy": classified_flag(sig.get("proxy")), "tor": classified_flag(sig.get("tor")),
            "bogon": classified_flag(sig.get("bogon")),
            "vpn": True if classification == "vpn" else classified_flag(sig.get("vpnasn")),
            "relay": classified_flag(sig.get("goodvpn")),
            "hosting": classified_flag(detected(sig.get("hosting"), sig.get("cloud"))),
            "mobile": True if classification == "mobile" else classified_flag(sig.get("mobileasn")),
        }),
        "classification": classification, "classificationConfidence": num(d.get("confidence")),
    }

def src_netatlas(ip, ctx):
    r = get_json(f"https://atlas.ipinfo.app/api/v2/ip/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("error") or not d.get("ip"):
        raise SourceFail("Net Atlas 未返回有效目标")
    if not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    baseline = loc.get("source") == "baseline"
    return {
        "country": country_code(loc.get("country_code")), "region": text(loc.get("region")), "city": text(loc.get("city")),
        "lat": num(loc.get("latitude")), "lon": num(loc.get("longitude")),
        "asn": asn_number(d.get("as_number")), "org": text(d.get("as_description")),
        "prefix": text(d.get("cidr")), "networkCountry": country_code(d.get("country_code")),
        "flags": flags_of(), "geoVote": baseline,
        "locationSource": text(loc.get("source")),
        "locationDatabase": "DB-IP City Lite" if baseline else None,
    }

def src_rdap(ip, ctx):
    r = get_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", timeout=20,
                 headers={"Accept": "application/rdap+json"})
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("errorCode"):
        raise SourceFail(f"RDAP {d['errorCode']}")
    events = {e.get("eventAction"): e.get("eventDate") for e in (d.get("events") or []) if isinstance(e, dict)}
    flat = []

    def walk(entities):
        for ent in entities or []:
            flat.append(ent)
            walk(ent.get("entities"))
    walk(d.get("entities"))

    def vcard(ent):
        out = {}
        for item in ((ent or {}).get("vcardArray") or [None, []])[1] or []:
            if not isinstance(item, list) or not item:
                continue
            if item[0] == "adr":
                out["adr"] = (item[1] or {}).get("label") if isinstance(item[1], dict) else (item[3] if len(item) > 3 else None)
            else:
                out[item[0]] = item[3] if len(item) > 3 else None
        return out

    def find_registrant():
        for ent in flat:
            if "registrant" in (ent.get("roles") or []) and vcard(ent).get("kind") == "org":
                return ent
        for ent in flat:
            if "registrant" in (ent.get("roles") or []):
                return ent
        return None

    registrant = find_registrant()
    abuse = next((e for e in flat if "abuse" in (e.get("roles") or [])), None)
    org = vcard(registrant)
    adr = org.get("adr")
    addr_lines = [ln.strip() for ln in str(adr).split("\n") if ln.strip()] if isinstance(adr, str) else []
    cidr = None
    c0 = (d.get("cidr0_cidrs") or [{}])[0]
    if c0.get("v4prefix") or c0.get("v6prefix"):
        cidr = f"{c0.get('v4prefix') or c0.get('v6prefix')}/{c0.get('length')}"
    port43 = text(d.get("port43"))
    rir = None
    if port43:
        rir = re.sub(r"^whois\.", "", port43)
        rir = re.sub(r"\.net$|\.(?:net|org)$", "", rir, flags=re.I).upper()
    return {
        "regCountry": country_code(d.get("country")), "netname": text(d.get("name")),
        "handle": text(d.get("handle")),
        "status": text(d.get("type")) or ", ".join(d.get("status") or []),
        "range": f"{d.get('startAddress')} – {d.get('endAddress')}" if d.get("startAddress") and d.get("endAddress") else None,
        "cidr": cidr, "regDate": text(events.get("registration")), "changed": text(events.get("last changed")),
        "orgName": text(org.get("fn")), "orgCountry": country_code(addr_lines[-1]) if addr_lines else None,
        "abuseName": text(vcard(abuse).get("fn")), "abuseEmail": text(vcard(abuse).get("email")),
        "rir": rir, "flags": flags_of(), "geoVote": False,
    }

def src_ipguide(ip, ctx):
    r = get_json(f"https://ip.guide/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("ip") and not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    net = d.get("network") or {}
    a = net.get("autonomous_system") or {}
    loc = d.get("location") or {}
    return {
        "asn": asn_number(a.get("asn")), "org": text(a.get("organization")), "asName": text(a.get("name")),
        "asCountry": country_code(a.get("country")), "rir": text(a.get("rir")),
        "prefix": text(net.get("cidr")), "country": country_code(loc.get("country")),
        "city": text(loc.get("city")), "lat": num(loc.get("latitude")), "lon": num(loc.get("longitude")),
        "tz": text(loc.get("timezone")), "flags": flags_of(),
    }

def src_riperir(ip, ctx):
    r = get_json(ripe_url("rir-stats-country", {"resource": ip}), timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    located = None
    try:
        located = d["data"]["located_resources"][0]
    except (KeyError, IndexError, TypeError):
        located = None
    if not located or not located.get("location"):
        raise SourceFail("无记录")
    return {"regCountry": country_code(located.get("location")), "block": text(located.get("resource")),
            "flags": flags_of(), "geoVote": False}

def src_ripeprefix(ip, ctx):
    r = get_json(ripe_url("prefix-overview", {"resource": ip}), timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = (r["data"] or {}).get("data") or {}
    asns = d.get("asns") or []
    if not d.get("announced"):
        return {"announced": False, "flags": flags_of(), "geoVote": False}
    first = asns[0] if asns else {}
    return {"announced": True, "prefix": text(d.get("resource")), "asn": asn_number(first.get("asn")),
            "asName": text(first.get("holder")), "origins": len(asns), "flags": flags_of(), "geoVote": False}

def src_otx(ip, ctx):
    v = parse_ip(ip).version
    kind = "IPv6" if v == 6 else "IPv4"
    r = get_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(ip)}/general", timeout=20)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    pulses = (d.get("pulse_info") or {}).get("pulses") or []
    validation = [text(x.get("source") or x.get("name")) for x in (d.get("validation") or []) if isinstance(x, dict)]
    validation = [x for x in validation if x]
    benign = bool(d.get("false_positive")) or any(re.search(r"whitelist|alexa|majestic|akamai|false", n, re.I) for n in validation)
    tor_flag = any(re.search(r"tor", n, re.I) for n in validation) or None
    return {
        "pulses": num((d.get("pulse_info") or {}).get("count")) or 0,
        "pulseNames": [text(p.get("name")) for p in pulses if text(p.get("name"))][:4],
        "validation": validation, "benign": benign,
        "flags": flags_of({"tor": tor_flag}), "geoVote": False,
    }

def src_shodan(ip, ctx):
    r = get_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}", timeout=15)
    if r["status"] == 404:
        return {"ports": [], "tags": [], "vulns": [], "hostnames": [], "flags": flags_of(), "geoVote": False, "unseen": True}
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    tags = [str(t) for t in (d.get("tags") or []) if isinstance(t, str)]
    return {
        "ports": [p for p in (d.get("ports") or []) if isinstance(p, int)],
        "tags": tags,
        "vulns": [str(v) for v in (d.get("vulns") or [])],
        "hostnames": [str(h) for h in (d.get("hostnames") or [])][:5],
        "flags": flags_of({
            "proxy": True if "proxy" in tags else None, "vpn": True if "vpn" in tags else None,
            "tor": True if "tor" in tags else None, "hosting": True if "cloud" in tags else None,
            "abuser": True if ("compromised" in tags or "malware" in tags) else None,
        }),
        "geoVote": False,
    }

def src_sfs(ip, ctx):
    r = get_json(f"https://api.stopforumspam.org/api?ip={urllib.parse.quote(ip)}&json", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("success") != 1 or not d.get("ip"):
        raise SourceFail("查询失败")
    rec = d["ip"]
    appears = num(rec.get("appears")) or 0
    return {
        "appears": appears, "frequency": num(rec.get("frequency")) or 0,
        "confidence": num(rec.get("confidence")), "lastseen": text(rec.get("lastseen")),
        "flags": flags_of({"tor": True if rec.get("torexit") else None, "abuser": True if appears > 0 else None}),
        "geoVote": False,
    }

def src_onionoo(ip, ctx):
    addr = parse_ip(ip)
    v4 = addr.version == 4
    query = ".".join(str(ip).split(".")[:3]) + "." if v4 else ip
    r = get_json(f"https://onionoo.torproject.org/details?search={urllib.parse.quote(query)}&fields=nickname,or_addresses,exit_addresses,flags,running", timeout=20)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}

    def addresses(relay):
        out = []
        for a in (relay.get("or_addresses") or []):
            out.append(re.sub(r"^\[|\]?:\d+$", "", a).rstrip("]"))
        out.extend(relay.get("exit_addresses") or [])
        return out

    relays = [x for x in (d.get("relays") or []) if any(same_ip(a, ip) for a in addresses(x))]
    neighbours = [x for x in (d.get("relays") or [])
                  if x not in relays and any(a.startswith(query) for a in addresses(x))] if v4 else []
    exit_ = any("Exit" in (x.get("flags") or []) or any(same_ip(a, ip) for a in (x.get("exit_addresses") or [])) for x in relays)
    return {
        "relays": [x.get("nickname") for x in relays if x.get("nickname")][:3],
        "torRelay": len(relays) > 0,
        "flags": flags_of({"tor": exit_}), "hard": {"tor": exit_}, "geoVote": False,
        "neighbourRelays": len(neighbours),
        "neighbourExits": len([x for x in neighbours if "Exit" in (x.get("flags") or [])]),
    }

_PTR_HOSTING = re.compile(r"(^|[.-])(vps|server|srv|host|hosting|cloud|dedi(cated)?|colo|static\.\d|compute|ec2|googleusercontent|linode|vultr|contabo|hetzner|ovh|leaseweb|your-server|kimsufi|clients\.your-server|ip-\d+-\d+-\d+\.(eu|net))([.-]|\d|$)")
_PTR_RES = re.compile(r"(^|[.-])(dyn|dynamic|dhcp|pool|ppp|pppoe|adsl|dsl|vdsl|cable|cpe|fttx|ftth|fiber|fibre|home|broadband|res|customer|client|user|subscriber|bb|flets|ocn|kddi|softbank|hinet|dynamicip)([.-]|\d|$)")
_PTR_MOB = re.compile(r"(^|[.-])(mobile|wireless|lte|4g|5g|gprs|umts|cellular|mob)([.-]|\d|$)")

def src_ptr(ip, ctx):
    addr = parse_ip(ip)
    zone = "ip6.arpa" if addr.version == 6 else "in-addr.arpa"
    r = get_json(f"https://dns.google/resolve?name={reverse_name(ip)}.{zone}&type=PTR", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    hostname = None
    for a in (d.get("Answer") or []):
        if a.get("type") == 12:
            hostname = (a.get("data") or "").rstrip(".") or None
            break
    name = (hostname or "").lower()
    out = {"hostname": hostname, "geoVote": False}
    if not name:
        out.update({"flags": flags_of(), "type": None})
    elif _PTR_HOSTING.search(name):
        out.update({"flags": flags_of({"hosting": True}), "type": "hosting"})
    elif _PTR_RES.search(name):
        out.update({"flags": flags_of(), "type": "residential"})
    elif _PTR_MOB.search(name):
        out.update({"flags": flags_of({"mobile": True}), "type": "mobile"})
    else:
        out.update({"flags": flags_of(), "type": None})
    return out

def src_ipapimirror(ip, ctx):
    primary = ctx.get("results", {}).get("ipapi")
    if primary and primary.get("status") == "ok":
        raise SourceFail("主来源已返回，本轮无需补充")
    r = get_json(f"https://api.techniknews.net/ipgeo/{urllib.parse.quote(ip)}", timeout=15)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    if d.get("status") != "success":
        raise SourceFail("拒绝查询")
    if not d.get("ip"):
        raise SourceFail("补充来源未标明目标 IP")
    if not same_ip(d["ip"], ip):
        raise SourceFail("返回目标不匹配")
    usage = "hosting" if d.get("hosting") is True else ("mobile" if d.get("mobile") is True else None)
    return {
        "country": country_code(d.get("countryCode")), "region": text(d.get("regionName")), "city": text(d.get("city")),
        "lat": num(d.get("lat")), "lon": num(d.get("lon")), "tz": text(d.get("timezone")),
        "asn": asn_number(d.get("as")), "org": text(d.get("org")) or text(d.get("isp")),
        "type": usage, "usageType": usage,
        "flags": flags_of({"proxy": d.get("proxy"), "hosting": d.get("hosting"), "mobile": d.get("mobile")}),
        "hostname": text(d.get("reverse")),
    }

SOURCES = [
    ("proxycheck", "Proxycheck", src_proxycheck),
    ("ipapi", "ip-api.com", src_ipapi),
    ("ip2location", "IP2Location", src_ip2location),
    ("dbip", "DB-IP", src_dbip),
    ("abuseipdb", "AbuseIPDB", src_abuseipdb),
    ("ipqs", "IPQualityScore", None),          # worker 未配置，仅 IPOK 补充
    ("ipregistry", "IPRegistry", None),        # worker 未配置，无补充
    ("ipdata", "IPData", None),                # worker 未配置，无补充
    ("ipquery", "IPQuery", src_ipquery),
    ("ipapiis", "ipapi.is", src_ipapiis),
    ("ipinfo", "IPinfo", src_ipinfo),
    ("ipwhois", "ipwho.is", src_ipwhois),
    ("ipsb", "IP.SB", src_ipsb),
    ("ipleak", "ipleak (MaxMind)", src_ipleak),
    ("geojs", "GeoJS", src_geojs),
    ("ipapico", "ipapi.co", src_ipapico),
    ("iplocation", "iplocation.net", src_iplocation),
    ("freeipapi", "FreeIPAPI", src_freeipapi),
    ("maxmind", "GeoLite2 (RIPEstat)", src_maxmind),
    ("iplocate", "IPLocate", src_iplocate),
    ("geoiplookup", "GeoIPLookup", src_geoiplookup),
    ("ipapimirror", "TechnikNews IPgeo", src_ipapimirror),
    ("blackbox", "Blackbox v3 beta", src_blackbox),
    ("netatlas", "Net Atlas", src_netatlas),
    ("rdap", "RDAP (RIR)", src_rdap),
    ("ipguide", "ip.guide", src_ipguide),
    ("riperir", "RIR 分配记录", src_riperir),
    ("ripeprefix", "RIPEstat 路由", src_ripeprefix),
    ("otx", "AlienVault OTX", src_otx),
    ("greynoise", "GreyNoise", None),          # worker 未配置，无补充
    ("crowdsec", "CrowdSec CTI", None),        # worker 未配置，无补充
    ("virustotal", "VirusTotal", None),        # worker 未配置，无补充
    ("scamalytics", "Scamalytics", None),      # worker 未配置，仅 IPOK 补充
    ("vpnapi", "vpnapi.io", None),             # worker 未配置，仅 IPOK 补充
    ("iphub", "IPHub", None),                 # worker 未配置，仅 IPOK 补充
    ("getipintel", "GetIPIntel", src_getipintel),
    ("shodan", "Shodan InternetDB", src_shodan),
    ("sfs", "StopForumSpam", src_sfs),
    ("onionoo", "Tor Project", src_onionoo),
    ("ptr", "反向解析 PTR", src_ptr),
]
SOURCE_NAMES = {sid: name for sid, name, _ in SOURCES}

# ---------------- IPOK 补充（supplements.js 移植） ----------------

IPOK_MAP = {"IPQS": "ipqs", "IPQualityScore": "ipqs", "Scamalytics": "scamalytics", "IPHub": "iphub",
            "vpnapi.io": "vpnapi", "ip-api": "ipapi", "ip-api.com": "ipapi", "ipapi.is": "ipapiis",
            "proxycheck": "proxycheck", "Proxycheck": "proxycheck", "AbuseIPDB": "abuseipdb"}

def lookup_ipok(ip):
    r = get_json(f"https://ipok.io/api/ip?ip={urllib.parse.quote(ip)}", timeout=25)
    if not r["ok"]:
        raise SourceFail(str(r["error"]))
    d = r["data"] or {}
    geo = d.get("geo") or {}
    if not same_ip(geo.get("ip") or geo.get("query"), ip):
        raise SourceFail("IPOK 返回目标不一致")
    rows = {}
    for att in (d.get("sourceAttempts") or []):
        sid = IPOK_MAP.get(att.get("source"))
        if sid:
            rows[sid] = {"unavailable": True, "reason": str(att.get("reason") or att.get("status") or "")}
    type_map = {"isp": "residential", "residential": "residential", "mobile": "mobile",
                "business": "business", "hosting": "hosting", "education": "education", "government": "government"}
    for row in (d.get("sources") or []):
        sid = IPOK_MAP.get(row.get("source"))
        if not sid or row.get("ok") is not True:
            continue
        obs = row.get("observedAt")
        obs_ms = obs if isinstance(obs, (int, float)) else None
        if obs_ms is None and isinstance(obs, str):
            try:
                from datetime import datetime
                obs_ms = datetime.fromisoformat(obs.replace("Z", "+00:00")).timestamp() * 1000
            except ValueError:
                obs_ms = None
        now_ms = time.time() * 1000
        if obs_ms is None or not math.isfinite(obs_ms) or obs_ms > now_ms + 60000 or now_ms - obs_ms > 72 * 3600000:
            rows[sid] = {"unavailable": True, "reason": "第三方观测时间不明或超过 72 小时"}
            continue
        fl = {}
        for k in ("vpn", "proxy", "tor", "hosting", "relay", "abuser", "crawler", "mobile"):
            if isinstance((row.get("flags") or {}).get(k), bool):
                fl[k] = row["flags"][k]
        percent = row.get("risk") if isinstance(row.get("risk"), (int, float)) and 0 <= row["risk"] <= 100 else None
        fields = {"usageType": type_map.get(str(row.get("usageType") or row.get("networkType") or "").lower()),
                  "companyType": type_map.get(str(row.get("companyType") or "").lower())}
        if fl.get("hosting") is True and not fields["usageType"]:
            fields["usageType"] = "hosting"
        if fl.get("mobile") is True and not fields["usageType"]:
            fields["usageType"] = "mobile"
        if percent is not None or fl or fields["usageType"] or fields["companyType"]:
            from datetime import datetime, timezone
            rows[sid] = {"flags": fl, "percent": percent, "fields": fields,
                         "observedAt": datetime.fromtimestamp(obs_ms / 1000, tz=timezone.utc).isoformat()}
    return rows

def fill_source(record, extra, note):
    """supplements.js fillSource：只填 null 字段；填了东西就把记录变成 ok。"""
    data = dict(record.get("data") or {})
    data["flags"] = dict((record.get("data") or {}).get("flags") or {})
    added = False
    for key, value in extra.items():
        if key == "flags":
            for fk, fv in (value or {}).items():
                if data["flags"].get(fk) is None and fv is not None:
                    data["flags"][fk] = fv
                    added = True
        elif value is not None and data.get(key) is None:
            data[key] = value
            added = True
    if not added:
        return record
    notes = [data.get("sourceNote"), note]
    data["sourceNote"] = " · ".join(n for n in notes if n)
    out = dict(record)
    out.update({"status": "ok", "directStatus": record.get("directStatus") or record.get("status"),
                "directError": record.get("directError") or record.get("error"), "error": None, "data": data})
    return out

# ---------------- DNSBL + CIDR 列表（blocklists.js 移植） ----------------

DNSBLS = [
    {"id": "spamcop", "name": "SpamCop", "zone": "bl.spamcop.net", "kind": "mail"},
    {"id": "barracuda", "name": "Barracuda", "zone": "b.barracudacentral.org", "kind": "mail"},
    {"id": "psbl", "name": "PSBL", "zone": "psbl.surriel.com", "kind": "mail"},
    {"id": "mailspike", "name": "Mailspike", "zone": "bl.mailspike.net", "kind": "mail"},
    {"id": "uceprotect", "name": "UCEPROTECT L1", "zone": "dnsbl-1.uceprotect.net", "kind": "mail"},
    {"id": "gbudb", "name": "GBUdb Truncate", "zone": "truncate.gbudb.net", "kind": "mail"},
    {"id": "nordspam", "name": "NordSpam", "zone": "bl.nordspam.com", "kind": "mail"},
    {"id": "justspam", "name": "JustSpam", "zone": "dnsbl.justspam.org", "kind": "mail"},
    {"id": "sem", "name": "SpamEatingMonkey", "zone": "bl.spameatingmonkey.net", "kind": "mail"},
    {"id": "spfbl", "name": "SPFBL", "zone": "dnsbl.spfbl.net", "kind": "mail", "ignore": ["127.0.0.4"]},
    {"id": "zerospam", "name": "0spam", "zone": "bl.0spam.org", "kind": "mail"},
    {"id": "interserver", "name": "InterServer", "zone": "rbl.interserver.net", "kind": "abuse"},
    {"id": "blocklistde", "name": "blocklist.de", "zone": "bl.blocklist.de", "kind": "abuse"},
    {"id": "s5h", "name": "S5H", "zone": "all.s5h.net", "kind": "abuse"},
    {"id": "dronebl", "name": "DroneBL", "zone": "dnsbl.dronebl.org", "kind": "abuse", "proxyCodes": [8, 9, 10, 11, 14, 19]},
    {"id": "dantor", "name": "dan.me.uk Tor", "zone": "torexit.dan.me.uk", "kind": "tor"},
]

def _doh_resolve_a(name):
    for tmpl in ("https://dns.google/resolve?name={}&type=A",
                 "https://cloudflare-dns.com/dns-query?name={}&type=A"):
        r = get_json(tmpl.format(urllib.parse.quote(name)), timeout=10,
                     headers={"Accept": "application/dns-json"})
        if not r["ok"] or not isinstance((r["data"] or {}).get("Status"), int):
            continue
        if r["data"]["Status"] == 3:
            return []
        if r["data"]["Status"] != 0:
            continue
        return [a.get("data") for a in (r["data"].get("Answer") or []) if a.get("type") == 1 and a.get("data")]
    return None

def check_dnsbl(lst, ip):
    addr = parse_ip(ip)
    if addr.version == 6 and lst["zone"] != "torexit.dan.me.uk":
        return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "status": "skip", "error": "仅支持 IPv4"}
    ans = _doh_resolve_a(f"{reverse_name(ip)}.{lst['zone']}")
    if ans is None:
        return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "status": "error", "error": "解析失败"}
    codes = [a for a in ans if a.startswith("127.") and not a.startswith("127.255.") and a != "127.0.0.1"
             and a not in (lst.get("ignore") or [])]
    last = []
    for c in codes:
        try:
            last.append(int(c.split(".")[3]))
        except (IndexError, ValueError):
            pass
    return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "status": "ok",
            "listed": len(codes) > 0, "codes": codes,
            "proxy": bool(lst.get("proxyCodes") and any(c in lst["proxyCodes"] for c in last))}

FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{}"
CIDR_LISTS = [
    {"id": "firehol1", "name": "FireHOL Level 1", "kind": "attack", "pts": 15, "url": FIREHOL.format("firehol_level1.netset")},
    {"id": "firehol2", "name": "FireHOL Level 2", "kind": "attack", "pts": 10, "url": FIREHOL.format("firehol_level2.netset")},
    {"id": "firehol3", "name": "FireHOL Level 3", "kind": "attack", "pts": 6, "url": FIREHOL.format("firehol_level3.netset")},
    {"id": "blocklistde", "name": "blocklist.de", "kind": "attack", "pts": 10, "density": True, "url": FIREHOL.format("blocklist_de.ipset")},
    {"id": "greensnow", "name": "GreenSnow", "kind": "attack", "pts": 8, "density": True, "url": FIREHOL.format("greensnow.ipset")},
    {"id": "cybercrime", "name": "CyberCrime C&C", "kind": "attack", "pts": 15, "density": True, "url": FIREHOL.format("cybercrime.ipset")},
    {"id": "sfs7d", "name": "StopForumSpam 7 天", "kind": "spam", "pts": 0, "density": True, "url": FIREHOL.format("stopforumspam_7d.ipset")},
    {"id": "dshield", "name": "DShield 攻击网段", "kind": "attack", "pts": 0, "url": FIREHOL.format("dshield_7d.netset")},
    {"id": "ipsum3", "name": "IPsum ≥3 黑名单", "kind": "attack", "pts": 8, "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"id": "etcompromised", "name": "ET 已入侵主机", "kind": "attack", "pts": 10, "density": True, "url": FIREHOL.format("et_compromised.ipset")},
    {"id": "ciarmy", "name": "CINS Army", "kind": "attack", "pts": 8, "density": True, "url": FIREHOL.format("ciarmy.ipset")},
    {"id": "botscout", "name": "BotScout 7 天", "kind": "spam", "pts": 6, "density": True, "url": FIREHOL.format("botscout_7d.ipset")},
    {"id": "socksproxy", "name": "公开 SOCKS 代理", "kind": "proxy", "url": FIREHOL.format("socks_proxy_7d.ipset")},
    {"id": "sslproxy", "name": "公开 HTTPS 代理", "kind": "proxy", "url": FIREHOL.format("sslproxies_7d.ipset")},
    {"id": "torexits", "name": "Tor 出口（FireHOL）", "kind": "tor", "url": FIREHOL.format("tor_exits.ipset")},
    {"id": "x4bdc", "name": "X4BNet 机房段", "kind": "datacenter", "url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"},
    {"id": "x4bvpn", "name": "X4BNet VPN 段", "kind": "vpn", "url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"},
]
LIST_TTL = 12 * 3600

def _parse_ranges(body):
    ranges = []
    for line in body.split("\n"):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        parts = entry.split("/", 1)
        octets = parts[0].split(".")
        if len(octets) != 4:
            continue
        try:
            start = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(octets))
            length = 32 if len(parts) == 1 else int(parts[1])
        except ValueError:
            continue
        if not (0 <= length <= 32):
            continue
        size = 2 ** (32 - length)
        base = (start // size) * size
        ranges.append((base, base + size - 1))
    ranges.sort()
    return ranges

_list_cache = {}

def load_cidr_list(lst):
    if lst["id"] in _list_cache:
        return _list_cache[lst["id"]]
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, lst["id"] + ".txt")
    body = None
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < LIST_TTL:
        with open(path, encoding="utf-8", errors="replace") as f:
            body = f.read()
    if body is None:
        ok, data, _ = fetch(lst["url"], timeout=30, as_text=True)
        if not ok:
            _list_cache[lst["id"]] = None
            return None
        body = data
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(body)
        except OSError:
            pass
    ranges = _parse_ranges(body)
    _list_cache[lst["id"]] = ranges
    return ranges

def _last_start_at_or_before(ranges, value):
    lo, hi, idx = 0, len(ranges) - 1, -1
    while lo <= hi:
        mid = (lo + hi) >> 1
        if ranges[mid][0] <= value:
            idx, lo = mid, mid + 1
        else:
            hi = mid - 1
    return idx

def _intersecting(ranges, a, b):
    out = []
    i = _last_start_at_or_before(ranges, b)
    behind = 0
    while i >= 0 and behind < 64:
        if ranges[i][0] < a:
            behind += 1
        if ranges[i][1] >= a:
            out.append(ranges[i])
        i -= 1
    return out

def check_cidr_list(lst, ip):
    addr = parse_ip(ip)
    if addr.version != 4:
        return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "pts": lst.get("pts"),
                "status": "skip", "error": "仅收录 IPv4"}
    ranges = load_cidr_list(lst)
    if ranges is None:
        return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "pts": lst.get("pts"),
                "status": "error", "error": "列表下载失败"}
    value = int(addr)
    hits = _intersecting(ranges, value, value)
    hit = hits[0] if hits else None
    block = (value // 256) * 256
    neighbours = set()
    whole = False
    for start, end in _intersecting(ranges, block, block + 255):
        if start <= block and end >= block + 255:
            whole = True
            continue
        for a in range(max(start, block), min(end, block + 255) + 1):
            if a != value:
                neighbours.add(a)
    return {"id": lst["id"], "name": lst["name"], "kind": lst["kind"], "pts": lst.get("pts"), "status": "ok",
            "listed": bool(hit),
            "match": f"{int_to_ip(hit[0])} – {int_to_ip(hit[1])}" if hit else None,
            "size": len(ranges),
            "neighbours": {"prefix": f"{int_to_ip(block)}/24",
                           "ips": [int_to_ip(a) for a in sorted(neighbours)], "whole": whole}}

def merge_routes(routes):
    ranges = []
    for cidr in routes or []:
        parts = str(cidr).split("/", 1)
        octets = parts[0].split(".")
        if len(octets) != 4:
            continue
        try:
            length = int(parts[1]) if len(parts) > 1 else 32
            start = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(octets))
        except ValueError:
            continue
        size = 2 ** (32 - length)
        base = (start // size) * size
        ranges.append([base, base + size - 1])
    ranges.sort()
    merged = []
    for r in ranges:
        if merged and r[0] <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], r[1])
        else:
            merged.append(list(r))
    return merged

ROUTED_IPV4 = 3.0e9

def _overlap_count(ranges, space):
    total = 0
    j = 0
    for start, end in ranges:
        while j < len(space) and space[j][1] < start:
            j += 1
        k = j
        while k < len(space) and space[k][0] <= end:
            total += min(end, space[k][1]) - max(start, space[k][0]) + 1
            k += 1
    return total

def asn_abuse_density(routes):
    space = merge_routes(routes)
    size = sum(e - s + 1 for s, e in space)
    if not size:
        return None
    lists = [l for l in CIDR_LISTS if l.get("density")]
    counts = {}
    listed = 0
    glob = 0
    for lst in lists:
        ranges = load_cidr_list(lst)
        if ranges is None:
            continue
        c = _overlap_count(ranges, space)
        counts[lst["name"]] = c
        listed += c
        glob += sum(e - s + 1 for s, e in ranges)
    if not glob:
        return None
    per10k = listed / size * 1e4
    baseline = glob / ROUTED_IPV4 * 1e4
    return {"size": size, "listed": listed, "counts": counts,
            "per10k": js_round(per10k * 100) / 100, "baseline": js_round(baseline * 1000) / 1000,
            "ratio": js_round(per10k / baseline * 10) / 10 if baseline else None}

# ---------------- ASN 画像（asn.js 移植） ----------------

def _tokens(value):
    stop = {"inc", "ltd", "llc", "limited", "the", "and", "corp", "corporation", "company",
            "network", "networks", "global", "international", "internet", "services", "asn"}
    words = re.sub(r"[^a-z0-9 ]", " ", str(value or "").lower()).split()
    return {w for w in words if len(w) > 2 and w not in stop}

def infer_asn(asn, names=None, pdb=None, v4ips=None, bot_share=None, ipapi_type=None,
              ipinfo_type=None, company_types=None, reg_date=None):
    names = names or []
    company_types = company_types or []
    votes = {}
    reasons = []
    independent = False
    own = {"votes": {}, "by": []}
    seen = {}

    def vote(cls, weight, reason=None, self=False):
        nonlocal independent
        votes[cls] = votes.get(cls, 0) + weight
        if reason:
            reasons.append(reason)
        if self:
            own["votes"][cls] = own["votes"].get(cls, 0) + weight
            if reason:
                own["by"].append(reason)
        else:
            independent = True
            seen[cls] = seen.get(cls, 0) + weight

    known = KNOWN_ASN.get(asn)
    if known:
        vote(known, 3, f"AS{asn} 在已知{CLASS_LABEL[known]}名单中")
    if asn in TRANSIT_HOSTING:
        vote("hosting", 1.2, "该骨干网同时经营大量机房 / 跨境专线业务")
    if pdb:
        types = pdb.get("types") or ([pdb["type"]] if pdb.get("type") else [])
        for t in types:
            mapped = PDB_TYPES.get(t)
            if mapped:
                vote(mapped[0], mapped[1], f"PeeringDB 自报类型：{t}", self=True)
        if pdb.get("ratio") in ("Heavy Outbound", "Mostly Outbound"):
            vote("hosting", 0.8, f"PeeringDB 流量以出向为主（{pdb['ratio']}）", self=True)
        if pdb.get("ratio") in ("Heavy Inbound", "Mostly Inbound"):
            vote("isp", 0.8, f"PeeringDB 流量以入向为主（{pdb['ratio']}），典型的用户接入网", self=True)
    name_text = " | ".join(n for n in names if n)
    for cls, pattern, weight in KEYWORDS:
        m = pattern.search(name_text)
        if m:
            vote(cls, weight, f"名称含{CLASS_LABEL[cls]}特征：{m.group(0)}", self=True)
            break
    company_map = {"residential": "isp", "mobile": "mobile", "hosting": "hosting",
                   "business": "business", "education": "education", "government": "government"}
    for item in company_types:
        mapped = company_map.get(item.get("value"))
        if mapped:
            vote(mapped, 1.0, f"{item.get('by')} 公司类型：{item.get('value')}")
    if ipinfo_type:
        mapped = {"isp": "isp", "hosting": "hosting", "business": "business",
                  "edu": "education", "education": "education"}.get(ipinfo_type)
        if mapped:
            vote(mapped, 2.2, f"IPinfo ASN 类型：{ipinfo_type}")
    if ipapi_type:
        mapped = {"isp": "isp", "hosting": "hosting", "business": "business",
                  "education": "education", "government": "government"}.get(ipapi_type)
        if mapped:
            vote(mapped, 1.5, f"ipapi.is ASN 类型：{ipapi_type}")
    if isinstance(v4ips, (int, float)) and v4ips > 0:
        if v4ips >= 1_000_000:
            vote("isp", 0.5, f"宣告 {int(v4ips):,} 个 IPv4，规模属于大型运营商")
        elif v4ips <= 4096:
            vote("hosting", 0.4)
            vote("business", 0.4, f"仅宣告 {int(v4ips):,} 个 IPv4，小型网络")
    age_years = None
    if reg_date:
        try:
            from datetime import datetime
            age_years = (time.time() - datetime.fromisoformat(reg_date.replace("Z", "+00:00")).timestamp()) / (365.25 * 86400)
        except ValueError:
            age_years = None
    if age_years is not None and age_years < 5 and not known:
        vote("hosting", 0.4, f"ASN {reg_date[:10]} 才注册，新网络里机房与代理业务更常见")
    if isinstance(bot_share, (int, float)):
        if bot_share >= 0.6:
            vote("hosting", 1.5, f"Cloudflare Radar：机器流量占 {round(bot_share * 100)}%")
        elif bot_share <= 0.25:
            vote("isp", 0.6, f"Cloudflare Radar：机器流量仅 {round(bot_share * 100)}%")
    ranked = sorted(votes.items(), key=lambda kv: -kv[1])
    if not ranked:
        return {"cls": None, "label": "未知", "hosting": None, "confidence": 0,
                "reasons": ["没有足够的 ASN 信息"], "mix": []}
    total = sum(w for _, w in ranked)
    cls, top = ranked[0]
    hosting = ((votes.get("hosting", 0) + votes.get("cdn", 0) + 0.3 * votes.get("transit", 0)) / total)
    confidence = min(1, top / 4) * (top / total)
    if not independent:
        confidence *= 0.65
        reasons.append("只有 ASN 自报的信息（PeeringDB、名称），没有第三方佐证")
    mix = [{"value": k, "share": js_round(w / total * 100) / 100} for k, w in ranked]
    return {"cls": cls, "label": CLASS_LABEL[cls], "hosting": js_round(hosting * 100) / 100,
            "confidence": js_round(confidence * 100) / 100, "reasons": reasons, "votes": votes, "mix": mix}

BROKERS = re.compile(r"(ipxo|interlir|heficed|ipbroker|internet utilities|logicweb|ip-?volume|ipv4 ?(mall|market|depot)|abuseradar|cloud innovation|larus|netutils)", re.I)

def detect_lease(rdap, holder, sources_orgs=None, as_rir=None, as_country=None, geo_country=None):
    if not rdap:
        return None
    sources_orgs = sources_orgs or []
    reasons = []
    weights = []
    org_name = rdap.get("orgName") or rdap.get("netname")
    holder_tokens = _tokens(holder)
    overlap = any(w in holder_tokens for w in _tokens(org_name))
    sub = bool(re.search(r"SUB-ALLOCATED|ASSIGNED PA|REASSIGNED|REALLOCATED|ALLOCATED-BY-LIR", rdap.get("status") or ""))
    age_days = None
    if rdap.get("regDate"):
        try:
            from datetime import datetime
            age_days = (time.time() - datetime.fromisoformat(rdap["regDate"].replace("Z", "+00:00")).timestamp()) / 86400
        except ValueError:
            age_days = None
    recent = age_days is not None and age_days < 3 * 365
    broker_text = " ".join(x for x in [rdap.get("abuseName"), rdap.get("abuseEmail"), rdap.get("netname"),
                                       rdap.get("orgName")] + list(sources_orgs) if x)
    broker = bool(BROKERS.search(broker_text))

    def signal(w, reason):
        weights.append(w)
        reasons.append(reason)

    if org_name and holder and not overlap and sub:
        signal(0.4, f"地址段登记给 {org_name}，与宣告方 {holder} 不同")
    if recent and sub:
        signal(0.25, f"{rdap['regDate'][:10]} 才登记的子分配")
    if broker:
        signal(0.6, f"管理方为 IP 租赁平台（{BROKERS.search(broker_text).group(0)}）")
    ip_rir = (rdap.get("rir") or "").upper() or None
    if ip_rir and as_rir and ip_rir != as_rir.upper():
        signal(0.35, f"地址段属于 {ip_rir}，宣告它的 ASN 属于 {as_rir.upper()}")
    elif rdap.get("regCountry") and as_country and geo_country and rdap["regCountry"] != as_country and rdap["regCountry"] != geo_country:
        signal(0.25, f"地址段登记在 {rdap['regCountry']}，ASN 在 {as_country}，定位在 {geo_country}")
    conf = 1 - math.prod(1 - w for w in weights)
    conf = js_round(conf * 100) / 100
    return {"leased": conf >= 0.5, "possible": 0.3 <= conf < 0.5, "confidence": conf, "reasons": reasons}

def _unique_space(routes):
    ranges = []
    for cidr in routes or []:
        parts = str(cidr).split("/", 1)
        octets = parts[0].split(".")
        if len(octets) != 4:
            continue
        try:
            start = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(octets))
            length = int(parts[1]) if len(parts) > 1 else 32
        except ValueError:
            continue
        ranges.append((start, start + 2 ** (32 - length) - 1))
    ranges.sort()
    total = 0
    reach = -1
    for start, end in ranges:
        if end <= reach:
            continue
        total += end - max(start, reach + 1) + 1
        reach = end
    return total

_asn_cache = {}

def fetch_asn(asn, prefix, health):
    if asn in _asn_cache:
        return _asn_cache[asn]
    def ripe(call, params):
        return get_json(ripe_url(call, params), timeout=15)
    jobs = {
        "overview": lambda: ripe("as-overview", {"resource": f"AS{asn}"}),
        "routing": lambda: ripe("routing-status", {"resource": f"AS{asn}"}),
        "pdb": lambda: get_json(f"https://www.peeringdb.com/api/net?asn={asn}", timeout=15),
        "rdap": lambda: get_json(f"https://rdap.org/autnum/{asn}", timeout=15, headers={"Accept": "application/rdap+json"}),
        "rpki": lambda: ripe("rpki-validation", {"resource": f"AS{asn}", "prefix": prefix}) if prefix else None,
        "radar": lambda: get_json(f"{API_BASE}/v1/radar?asn={asn}", timeout=20, pace=True) if (not health or "radar" in (health.get("routes") or [])) else None,
        "guide": lambda: get_json(f"https://ip.guide/AS{asn}", timeout=20),
    }
    results = {}
    with cf.ThreadPoolExecutor(max_workers=7) as ex:
        futs = {k: ex.submit(fn) for k, fn in jobs.items()}
        for k, f in futs.items():
            try:
                results[k] = f.result()
            except Exception:
                results[k] = None
    profile = {"asn": asn, "sources": {}}
    for k, r in results.items():
        profile["sources"][k] = "skip" if r is None else ("ok" if r.get("ok") else "error")
    ov = results.get("overview")
    if ov and ov.get("ok"):
        profile["holder"] = text(((ov["data"] or {}).get("data") or {}).get("holder"))
    rt = results.get("routing")
    if rt and rt.get("ok"):
        d = (rt["data"] or {}).get("data") or {}
        space = d.get("announced_space") or {}
        profile["v4ips"] = num((space.get("v4") or {}).get("ips"))
        profile["v4prefixes"] = num((space.get("v4") or {}).get("prefixes"))
        profile["v6prefixes"] = num((space.get("v6") or {}).get("prefixes"))
    routes = None
    gd = results.get("guide")
    if gd and gd.get("ok") and isinstance(((gd["data"] or {}).get("routes") or {}).get("v4"), list):
        routes = gd["data"]["routes"]["v4"]
    if not routes:
        an = ripe("announced-prefixes", {"resource": f"AS{asn}"})
        if an.get("ok"):
            routes = [p.get("prefix") for p in (((an["data"] or {}).get("data") or {}).get("prefixes") or [])
                      if isinstance(p.get("prefix"), str) and ":" not in p["prefix"]]
    if routes:
        profile["routes"] = routes
        if not profile.get("v4ips"):
            profile["v4prefixes"] = len(routes)
            profile["v4ips"] = _unique_space(routes)
    pdb = results.get("pdb")
    if pdb and pdb.get("ok"):
        nets = (pdb["data"] or {}).get("data") or []
        if nets:
            net = nets[0]
            profile["pdb"] = {"name": text(net.get("name")), "type": text(net.get("info_type")),
                              "types": net.get("info_types") if isinstance(net.get("info_types"), list) else None,
                              "traffic": text(net.get("info_traffic")), "ratio": text(net.get("info_ratio")),
                              "scope": text(net.get("info_scope")), "website": text(net.get("website")),
                              "created": text(net.get("created"))}
    rd = results.get("rdap")
    if rd and rd.get("ok"):
        d = rd["data"] or {}
        ev = next((e for e in (d.get("events") or []) if e.get("eventAction") == "registration"), None)
        profile["regDate"] = text(ev.get("eventDate")) if ev else None
        profile["asCountry"] = text(d.get("country"))
        profile["rdapName"] = text(d.get("name"))
    rp = results.get("rpki")
    if rp and rp.get("ok"):
        profile["rpki"] = text(((rp["data"] or {}).get("data") or {}).get("status"))
    radar = results.get("radar")
    if radar and radar.get("ok") and isinstance((radar["data"] or {}).get("bot"), (int, float)):
        profile["botShare"] = radar["data"]["bot"]
        profile["radar"] = radar["data"]
    _asn_cache[asn] = profile
    return profile

# ---------------- 证据组装（main.js buildEvidence 移植，非自查路径） ----------------

def neighbour_summary(run):
    if run["v"] != 4:
        return None
    ips = set()
    lists = []
    whole = []
    prefix = None
    checked = 0
    for item in run["lists"]:
        if item.get("status") != "ok" or item.get("kind") not in ("attack", "spam", "proxy") or not item.get("neighbours"):
            continue
        checked += 1
        prefix = item["neighbours"]["prefix"]
        if item["neighbours"].get("whole"):
            whole.append(item["name"])
        if item["neighbours"].get("ips"):
            lists.append(f"{item['name']} {len(item['neighbours']['ips'])}")
            ips.update(item["neighbours"]["ips"])
    onionoo = run["sources"].get("onionoo") or {}
    tor = onionoo.get("data", {}).get("neighbourRelays", 0) if onionoo.get("status") == "ok" else 0
    abuse = run["sources"].get("abuseipdb") or {}
    block = abuse.get("data", {}).get("block") if abuse.get("status") == "ok" else None
    if not checked and not block:
        return None
    return {"prefix": prefix or (block or {}).get("prefix"), "count": max(len(ips), (block or {}).get("reported", 0) or 0),
            "sample": sorted(ips)[:6], "lists": lists, "whole": whole, "tor": tor,
            "abuseipdb": block, "checked": checked}

def majority_country(run):
    counts = {}
    for record in run["sources"].values():
        if record.get("status") == "ok" and (record.get("data") or {}).get("geoVote") is not False:
            code = (record.get("data") or {}).get("country")
            if code:
                counts[code] = counts.get(code, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda kv: -kv[1])[0][0]

def build_evidence(run):
    sources = {}
    for sid, record in run["sources"].items():
        r = dict(record)
        r["name"] = SOURCE_NAMES.get(sid, sid)
        sources[sid] = r
    extra = {"vpn": [], "proxy": [], "tor": [], "hosting": [], "abuser": []}
    for item in run["dnsbl"]:
        if item.get("status") != "ok":
            continue
        if item["id"] == "dantor":
            extra["tor"].append({"by": "dan.me.uk", "value": item.get("listed"), "w": 0.95 if item.get("listed") else 0.3,
                                "hard": bool(item.get("listed"))})
        if item.get("proxy"):
            extra["proxy"].append({"by": "DroneBL", "value": True, "w": 0.9, "obs": True})
    for item in run["lists"]:
        if item.get("status") != "ok":
            continue
        if item["id"] == "x4bdc":
            extra["hosting"].append({"by": "X4BNet 机房段", "value": item.get("listed"), "w": 0.7 if item.get("listed") else 0.25})
        if item["id"] == "x4bvpn":
            extra["vpn"].append({"by": "X4BNet VPN 段", "value": item.get("listed"), "w": 0.7 if item.get("listed") else 0.2})
        if item.get("kind") == "proxy" and item.get("listed"):
            extra["proxy"].append({"by": item["name"], "value": True, "w": 0.85, "obs": True})
        if item.get("kind") == "tor":
            extra["tor"].append({"by": item["name"], "value": item.get("listed"),
                                "w": 1 if item.get("listed") else 0.3, "hard": bool(item.get("listed"))})
    asn_profile = None
    if run.get("asn"):
        asn = run["asn"]
        def data(sid):
            rec = run["sources"].get(sid) or {}
            return rec.get("data") if rec.get("status") == "ok" else None
        ipguide = data("ipguide") or {}
        ipinfo = data("ipinfo") or {}
        ipapiis = data("ipapiis") or {}
        ripeprefix = data("ripeprefix") or {}
        names = [asn.get("holder"), (asn.get("pdb") or {}).get("name"), asn.get("rdapName"),
                 ipguide.get("asName"), ipguide.get("org"), ripeprefix.get("asName")]
        company_types = [{"by": SOURCE_NAMES.get(sid, sid), "value": (rec.get("data") or {}).get("companyType")}
                         for sid, rec in run["sources"].items()
                         if rec.get("status") == "ok" and (rec.get("data") or {}).get("companyType")]
        inferred = infer_asn(asn["asn"], names=names, pdb=asn.get("pdb"), v4ips=asn.get("v4ips"),
                             bot_share=asn.get("botShare"), ipapi_type=ipapiis.get("asnType"),
                             ipinfo_type=ipinfo.get("asnType"), company_types=company_types,
                             reg_date=asn.get("regDate"))
        lease = detect_lease(data("rdap"), asn.get("holder") or (ipguide.get("org") or ""),
                             sources_orgs=[(data("ipwhois") or {}).get("domain"), ipapiis.get("companyDomain")],
                             as_rir=ipguide.get("rir"),
                             as_country=asn.get("asCountry") or ipguide.get("asCountry"),
                             geo_country=majority_country(run))
        asn_profile = dict(asn)
        asn_profile.update({"inferred": inferred, "lease": lease,
                            "label": asn.get("holder").split(" - ")[-1] if asn.get("holder") else f"AS{asn['asn']}"})
    return {"ip": run["ip"], "v": run["v"], "self": False, "sources": sources,
            "dnsbl": run["dnsbl"], "lists": run["lists"], "extraVotes": extra,
            "asn": asn_profile, "asnRep": run.get("asnRep"),
            "neighbours": neighbour_summary(run), "seen": None, "probes": {}}

# ---------------- 评分（score.js 移植，非自查路径） ----------------

def asn_trust_of(asn_info, rep, bot_share):
    parts = []
    if rep and rep.get("size"):
        ratio = rep.get("ratio")
        value = clamp(-math.log10(ratio), -1, 1) if ratio and ratio > 0 else 1
        parts.append({"w": 0.45 if rep["size"] >= 4096 else 0.2, "value": value,
                      "text": f"滥用密度为全网平均的 {ratio} 倍"})
    inferred = (asn_info or {}).get("inferred") or {}
    if inferred.get("cls"):
        base = {"isp": 1, "mobile": 1, "education": 0.5, "government": 0.5, "business": 0.2,
                "transit": 0, "cdn": -0.3, "hosting": -0.6}.get(inferred["cls"], 0)
        parts.append({"w": 0.25, "value": base * (inferred.get("confidence") or 0),
                      "text": inferred.get("label") or inferred["cls"]})
    if not parts:
        return None
    if bot_share is not None:
        parts.append({"w": 0.2, "value": clamp((0.4 - bot_share) / 0.25, -1, 1),
                      "text": f"机器流量 {pct(bot_share)}"})
    reg = (asn_info or {}).get("regDate")
    if reg:
        try:
            from datetime import datetime
            years = (time.time() - datetime.fromisoformat(reg.replace("Z", "+00:00")).timestamp()) / (365.25 * 86400)
            parts.append({"w": 0.1, "value": clamp((years - 5) / 10, -1, 1),
                          "text": f"注册 {max(0, math.floor(years))} 年"})
        except ValueError:
            pass
    weight = sum(p["w"] for p in parts)
    value = sum(p["w"] * p["value"] for p in parts) / weight
    relief = ASN_RELIEF * clamp(value, 0, 1)
    return {"value": r3(value), "relief": r3(relief), "reasons": [p["text"] for p in parts]}

def tally(votes):
    known = [v for v in votes if isinstance(v.get("value"), bool)]
    positive = [v for v in known if v["value"]]
    hard = any(v.get("hard") for v in positive)
    observed = [v for v in positive if v.get("obs")]
    H = 0.0
    for v in positive:
        w = min(0.95, v.get("w", 0.5))
        H += w / (1 - w) if v.get("obs") else v.get("w", 0.5)
    N = sum(v.get("w", 0.5) for v in known if not v["value"])
    E = 1 if hard else (H / (H + N) if H > 0 else 0)
    return {"E": r3(E), "H": r3(H), "N": r3(N), "yes": len(positive), "of": len(known), "hard": hard,
            "by": [v.get("by") for v in positive], "observedBy": [v.get("by") for v in observed],
            "clear": [v.get("by") for v in known if not v["value"]]}

def vote_text(t, verb="来源命中"):
    share = "直接确认" if t["hard"] else f"加权占比 {round(t['E'] * 100)}%"
    by = f"：{'、'.join(t['by'])}" if t["by"] else ""
    return f"{t['yes']}/{t['of']} {verb}{by} · {share}"

def ok_sources(evidence):
    out = []
    for sid, src in (evidence.get("sources") or {}).items():
        if src and src.get("status") == "ok" and src.get("data"):
            rec = {"id": sid, "name": src.get("name") or sid}
            rec.update(src["data"])
            out.append(rec)
    return out

def flag_votes(sources, flag):
    votes = []
    for s in sources:
        value = (s.get("flags") or {}).get(flag)
        if not isinstance(value, bool):
            continue
        weights = SOURCE_WEIGHTS.get(s["id"]) or {"flags": 0.5}
        if weights.get("positiveOnly") and value is False:
            continue
        votes.append({"by": s["name"], "value": value, "w": weights.get("flags", 0.5),
                      "hard": bool((s.get("hard") or {}).get(flag)) and value,
                      "obs": bool(weights.get("observed")) and value})
    return votes

def weighted_rank(entries):
    totals = {}
    order = []
    for e in entries:
        if e["value"] not in totals:
            totals[e["value"]] = {"value": e["value"], "w": 0, "by": []}
            order.append(e["value"])
        totals[e["value"]]["w"] += e["w"]
        totals[e["value"]]["by"].append(e["by"])
    total = sum(t["w"] for t in totals.values())
    out = []
    for t in totals.values():
        out.append({**t, "share": t["w"] / total if total else 0})
    out.sort(key=lambda x: (-x["w"], str(x["value"])))
    return out

def sharing_of(seen, devices, known_shared):
    own = (seen or {}).get("sharers", 0) if seen else 0
    address = (devices or {}).get("address")
    subnet = (devices or {}).get("subnet")
    count = max(own, address or 0)
    if seen is None and address is None and subnet is None:
        tier = None
    elif own > 10 or (address is not None and address >= 10) or (subnet is not None and subnet >= 500):
        tier = "多人共享"
    elif known_shared:
        tier = "可能多人共用"
    elif count >= 4:
        tier = "正常"
    elif subnet is not None and subnet >= 100:
        tier = "同段较多"
    elif count >= 2:
        tier = "少量共享"
    elif address == 0:
        tier = "未见记录"
    elif address is None or subnet is None:
        tier = "数据不足"
    else:
        tier = "疑似独享"
    low = address is not None and address >= 1 and subnet is not None and tier in ("疑似独享", "少量共享")
    level = {"多人共享": "bad" if own > 20 else "warn", "少量共享": "good" if low else "info",
             "疑似独享": "good", "数据不足": "none", "未见记录": "none"}.get(tier, "info" if tier else "none")
    return {"own": own, "address": address, "subnet": subnet, "tier": tier, "level": level, "low": low}

def unsure_label(certainty, what):
    if certainty < UNSURE:
        return {"k": max(0, certainty) / UNSURE, "why": f"{what}确定度 {pct(certainty)}"}
    return None

def doubt_of(doubts):
    lst = [d for d in (doubts or []) if d]
    k = 1.0
    for d in lst:
        k *= d["k"]
    if k < 0.995:
        return {"k": r3(k), "why": f"按 {pct(k)} 计：{'；'.join(d['why'] for d in lst)}"}
    return None

def grade_of(value):
    if value >= 95:
        return {"letter": "S", "label": "极度纯净"}
    if value >= 85:
        return {"letter": "A", "label": "纯净"}
    if value >= 70:
        return {"letter": "B", "label": "良好"}
    if value >= 55:
        return {"letter": "C", "label": "一般"}
    if value >= 40:
        return {"letter": "D", "label": "可疑"}
    return {"letter": "F", "label": "高危"}

def score(evidence):
    sources = ok_sources(evidence)
    items = {c["id"]: [] for c in CATEGORIES}
    notes = []

    def add(category, sid, label, pts, detail, doubts=None):
        doubt = doubt_of(doubts)
        value = pts * (doubt["k"] if doubt else 1)
        if value > 0.05:
            item = {"id": sid, "label": label, "pts": r1(value), "detail": detail}
            if doubt:
                item.update({"unsure": True, "full": r1(pts), "k": doubt["k"], "why": doubt["why"]})
            items[category].append(item)

    def note(level, txt):
        notes.append({"level": level, "text": txt})

    # ---- 定位共识（同库家族去重） ----
    def geo_weight(s):
        return (SOURCE_WEIGHTS.get(s["id"]) or {}).get("geo", 1)
    family_seen = {}
    for s in sources:
        if not s.get("country") or s.get("geoVote") is False:
            continue
        fam = GEO_FAMILY.get(s["id"], s["id"])
        entry = {"value": s["country"], "w": geo_weight(s), "by": s["name"], "city": s.get("city"),
                 "lat": s.get("lat"), "lon": s.get("lon"), "tz": s.get("tz")}
        if fam not in family_seen or entry["w"] > family_seen[fam]["w"]:
            family_seen[fam] = entry
    countries = weighted_rank(list(family_seen.values()))
    country = countries[0]["value"] if countries else None
    country_support = countries[0]["share"] if countries else None
    geo_count = len([s for s in sources if s.get("country") and s.get("geoVote") is not False])

    def field_rank(field):
        fams = {}
        for s in sources:
            if s.get("geoVote") is False or not s.get(field) or s.get("country") != country:
                continue
            fam = GEO_FAMILY.get(s["id"], s["id"])
            entry = {"value": s[field], "w": geo_weight(s), "by": s["name"]}
            if fam not in fams or entry["w"] > fams[fam]["w"]:
                fams[fam] = entry
        return weighted_rank(list(fams.values()))
    city_rank = field_rank("city")
    city = city_rank[0]["value"] if city_rank else None
    tz_rank = field_rank("tz")
    ip_tz = tz_rank[0]["value"] if tz_rank else None
    asn_rank = weighted_rank([{"value": s["asn"], "w": geo_weight(s), "by": s["name"]}
                              for s in sources if s.get("asn")])
    asn_info = evidence.get("asn") or {}
    asn = asn_info.get("asn") or (asn_rank[0]["value"] if asn_rank else None)
    org_rank = weighted_rank([{"value": s["org"], "w": geo_weight(s), "by": s["name"]}
                              for s in sources if s.get("org")])
    hostname = next((s.get("hostname") for s in sources if s.get("hostname")), None)

    asn_cls = (asn_info.get("inferred") or {}).get("cls")
    asn_hosting = (asn_info.get("inferred") or {}).get("hosting")
    asn_conf = (asn_info.get("inferred") or {}).get("confidence", 0)
    rep = evidence.get("asnRep")
    bot_share = asn_info.get("botShare")
    bot_share = clamp(bot_share, 0, 1) if isinstance(bot_share, (int, float)) else None
    asn_trust = asn_trust_of(asn_info, rep, bot_share)
    asn_doubt = None
    if asn_trust and asn_trust["relief"] >= 0.02:
        asn_doubt = {"k": 1 - asn_trust["relief"],
                     "why": f"{asn_info.get('label') or 'ASN'} 信誉良好（{'、'.join(asn_trust['reasons'])}），这项可能是误判"}
    asn_type_doubt = unsure_label(asn_conf, "ASN 类型") if asn_cls else None

    if len(countries) > 1 and country_support is not None and country_support < 0.85:
        pts = clamp(6 * (0.85 - country_support) / 0.35, 0, 5)
        add("geo", "geo-split", "定位分歧", pts,
            " · ".join(f"{c['value']} ×{len(c['by'])}" for c in countries))

    # ---- 注册地（原生 vs 广播） ----
    reg_votes = []
    for s in sources:
        if not s.get("regCountry"):
            continue
        w = 1.0 if s["id"] == "ipleak" else 0.8 if s["id"] == "riperir" else 0.6 if s["id"] == "rdap" else 0.5
        reg_votes.append({"value": s["regCountry"], "w": w, "by": s["name"]})
    reg_rank = weighted_rank(reg_votes)
    reg_country = reg_rank[0]["value"] if reg_rank else None
    native = None
    native_share = None
    native_certainty = 0
    if reg_country and country:
        total = sum(i["w"] for i in reg_rank)
        match = next((i for i in reg_rank if i["value"] == country), None)
        native_share = r1(((match["w"] if match else 0) / total * 100)) / 100
        native_certainty = max(native_share, 1 - native_share) * min(1, len(reg_votes) / 2)
    if reg_country and country:
        native = reg_country == country
        if not native:
            add("geo", "broadcast", "广播 IP", 3 * (1 - native_share),
                f"注册地 {reg_country}，定位 {country}" + (f"；{round(native_share * 100)}% 的注册信息与定位一致" if native_share > 0 else ""),
                [unsure_label(native_certainty, "原生性")])
        if len(reg_rank) > 1:
            note("info", "注册信息不一致：" + " / ".join(f"{i['value']}（{'、'.join(i['by'])}）" for i in reg_rank))

    # ---- 匿名化 ----
    extra_votes = evidence.get("extraVotes") or {}
    anon_flags = {}
    for flag in ("vpn", "proxy", "tor", "relay", "crawler"):
        anon_flags[flag] = tally(flag_votes(sources, flag) + (extra_votes.get(flag) or []))
    tor = anon_flags["tor"]
    tor_hard = tor["hard"] or tor["E"] >= 0.7
    if tor["E"] > 0:
        add("anon", "tor", "Tor", 40 * tor["E"], vote_text(tor))

    def label_doubt(t):
        return None if (t["hard"] or t["observedBy"]) else asn_doubt

    vpn_pts = 24 * anon_flags["vpn"]["E"]
    proxy_pts = 26 * anon_flags["proxy"]["E"]
    overlap = vpn_pts > 0 and proxy_pts > 0
    if vpn_pts:
        half = overlap and vpn_pts < proxy_pts
        add("anon", "vpn", "VPN", vpn_pts / 2 if half else vpn_pts,
            vote_text(anon_flags["vpn"]) + ("；与代理证据重叠，按一半计" if half else ""), [label_doubt(anon_flags["vpn"])])
    res_proxy_by = [s["name"] for s in sources if s.get("resProxy") is True]
    if proxy_pts:
        half = overlap and proxy_pts <= vpn_pts
        add("anon", "proxy", "代理（含住宅代理）" if res_proxy_by else "代理", proxy_pts / 2 if half else proxy_pts,
            vote_text(anon_flags["proxy"]) + ("；与 VPN 证据重叠，按一半计" if half else ""), [label_doubt(anon_flags["proxy"])])
    if anon_flags["relay"]["E"] > 0:
        add("anon", "relay", "隐私中继", 5 * anon_flags["relay"]["E"], vote_text(anon_flags["relay"]),
            [label_doubt(anon_flags["relay"])])
    if anon_flags["crawler"]["E"] > 0:
        add("anon", "crawler", "爬虫 / 自动化", 8 * anon_flags["crawler"]["E"], vote_text(anon_flags["crawler"]),
            [label_doubt(anon_flags["crawler"])])
    anon_any = max(anon_flags["vpn"]["E"], anon_flags["proxy"]["E"])
    pc = next((s for s in sources if s["id"] == "proxycheck"), None)
    devices = (pc or {}).get("devices")
    if devices and isinstance(devices.get("address"), (int, float)) and devices["address"] >= 10:
        add("anon", "shared", "多设备共用出口", 5 if devices["address"] >= 50 else 3,
            f"Proxycheck 估计该地址近期约 {devices['address']} 台设备")
    seen = None  # 本脚本不调 /v1/seen
    sharers = 0

    # ---- 网络类型 ----
    hosting_votes = flag_votes(sources, "hosting") + (extra_votes.get("hosting") or [])
    type_votes = []
    for s in sources:
        if not s.get("type"):
            continue
        if s["id"] == "abuseipdb" and any(x["id"] == "ipinfo" and x.get("type") for x in sources):
            continue
        w = (SOURCE_WEIGHTS.get(s["id"]) or {}).get("type", 0.5)
        type_votes.append({"value": s["type"], "w": w, "by": s["name"]})
        has_host_flag = isinstance((s.get("flags") or {}).get("hosting"), bool)
        if s["type"] == "hosting" and not has_host_flag:
            hosting_votes.append({"by": s["name"], "value": True, "w": w})
        if s["type"] != "hosting" and not has_host_flag:
            hosting_votes.append({"by": s["name"], "value": False, "w": w * 0.6})
    hosting = tally(hosting_votes)
    non_host_rank = weighted_rank([{"value": {"isp": "residential", "government": "business"}.get(v["value"], v["value"]),
                                    "w": v["w"], "by": v["by"]} for v in type_votes if v["value"] != "hosting"])
    ip_type = None
    type_from = None
    if hosting["E"] >= 0.5:
        ip_type, type_from = "hosting", "sources"
    elif non_host_rank:
        ip_type, type_from = non_host_rank[0]["value"], "sources"
    elif hosting["of"] > 0:
        ip_type, type_from = "residential", "exclusion"
    elif asn_cls == "isp":
        ip_type, type_from = "residential", "asn"
    elif asn_cls == "mobile":
        ip_type, type_from = "mobile", "asn"
    elif asn_cls in ("hosting", "cdn"):
        ip_type, type_from = "hosting", "asn"
    elif asn_cls in ("business", "education"):
        ip_type, type_from = asn_cls, "asn"

    type_from_asn = {"isp": "residential", "mobile": "mobile", "hosting": "hosting", "cdn": "hosting",
                     "transit": "business", "business": "business", "government": "business", "education": "education"}
    type_mix = []
    type_certainty = 0
    home_certainty = 0
    if type_from in ("sources", "exclusion"):
        host_share = hosting["E"] if hosting["of"] else (1 if ip_type == "hosting" else 0)
        others = non_host_rank if non_host_rank else [{"value": "residential", "share": 1}]
        type_mix = [{"value": "hosting", "share": host_share}] + [
            {"value": i["value"], "share": (1 - host_share) * i["share"]} for i in others]
        evidence_count = hosting["of"] + len(type_votes)
        coverage = min(1, evidence_count / 4)
        type_certainty = 0.35 if type_from == "exclusion" else max(i["share"] for i in type_mix) * coverage
        home_share = sum(i["share"] for i in type_mix if i["value"] in ("residential", "mobile"))
        home_certainty = 0.35 if type_from == "exclusion" else home_share * coverage
    elif type_from == "asn":
        merged = {}
        for item in (asn_info.get("inferred") or {}).get("mix") or []:
            v = type_from_asn.get(item["value"])
            if v:
                merged[v] = merged.get(v, 0) + item["share"]
        type_mix = [{"value": k, "share": v} for k, v in merged.items()]
        type_certainty = ((asn_info.get("inferred") or {}).get("confidence") or 0) * 0.6
        if ip_type in ("residential", "mobile"):
            home_certainty = type_certainty
    type_mix = [{**i, "share": r1(i["share"] * 100) / 100} for i in type_mix if i["share"] > 0.005]
    type_mix.sort(key=lambda x: -x["share"])

    type_doubt = unsure_label(type_certainty, "类型标签")
    if hosting["E"] > 0:
        add("network", "hosting", "机房 IP", 15 * hosting["E"], vote_text(hosting, "来源标记机房"),
            [type_doubt, label_doubt(hosting)])
    elif ip_type == "hosting" and type_from == "asn":
        add("network", "hosting-asn", "机房 IP（按 ASN 推断）", 10 * (asn_hosting if asn_hosting is not None else 0.7),
            ((asn_info.get("inferred") or {}).get("reasons") or [""])[0], [type_doubt])

    asn_consistency = None
    if asn_cls and ip_type:
        home_like = ip_type in ("residential", "mobile")
        if home_like and asn_cls in ("hosting", "cdn") and (asn_hosting or 0) >= 0.5:
            asn_consistency = {"ok": False, "text": f"标为{TYPE_LABEL[ip_type]}，但 {asn_info.get('label') or 'ASN'} 以机房为主"}
            add("network", "asn-conflict", "类型与 ASN 不符", 5 * asn_hosting, asn_consistency["text"],
                [type_doubt if type_certainty <= asn_conf else asn_type_doubt])
        elif home_like and asn_cls == "transit":
            asn_consistency = {"ok": True, "warn": True,
                               "text": f"标为{TYPE_LABEL[ip_type]}，宣告方却是骨干 / 传输网：骨干网本身可靠，但家宽很少直接挂在它下面，这个标签存疑"}
        elif ip_type == "hosting" and asn_cls in ("isp", "mobile"):
            asn_consistency = {"ok": True, "warn": True, "text": "运营商 ASN 中的机房段（IDC / 云业务）"}
        elif home_like and asn_cls in ("isp", "mobile"):
            asn_consistency = {"ok": True, "text": "类型与 ASN 一致：运营商网络"}
        elif ip_type == "hosting" and asn_cls in ("hosting", "cdn"):
            asn_consistency = {"ok": True, "text": "类型与 ASN 一致：机房网络"}
        elif ip_type == "business" and asn_cls == "transit":
            asn_consistency = {"ok": True, "warn": True, "text": "骨干网直接宣告的商业段，常见于 IP 租赁与代理"}
        else:
            asn_consistency = {"ok": True, "text": f"ASN 类型：{(asn_info.get('inferred') or {}).get('label') or asn_cls}"}

    rdap_src = next((s for s in sources if s["id"] == "rdap"), None)
    lease = (asn_info.get("lease") if asn_info else None)
    lease_certainty = 1 if not lease else (1 if lease["confidence"] >= 0.7 else 0.5)
    lease_doubt = None
    if lease and lease_certainty < UNSURE:
        lease_doubt = {"k": lease_certainty / UNSURE, "why": f"租赁把握 {pct(lease['confidence'])}"}
    if lease and (lease.get("leased") or lease.get("possible")):
        add("network", "leased", "租赁 / 转售地址段" if lease.get("leased") else "可能是租赁地址段",
            3 * clamp(lease["confidence"] / 0.7, 0, 1), "；".join(lease["reasons"]), [lease_doubt])
    if asn_info.get("regDate"):
        try:
            from datetime import datetime
            if time.time() - datetime.fromisoformat(asn_info["regDate"].replace("Z", "+00:00")).timestamp() < 2 * 365 * 86400:
                add("network", "asn-young", "新注册 ASN", 2, f"ASN 注册于 {asn_info['regDate'][:10]}")
        except ValueError:
            pass

    # ---- 邻居与 ASN 信誉 ----
    nb = evidence.get("neighbours")
    if nb:
        if nb.get("whole"):
            add("neighbours", "block-listed", "整个网段被列入威胁列表", 15,
                f"{nb['prefix']} 整段在 {'、'.join(nb['whole'])}")
        if nb.get("count"):
            c = nb["count"]
            pts = 14 if c >= 30 else 10 if c >= 10 else 6 if c >= 3 else 3
            detail = f"{nb['prefix']} 内另有 {c} 个地址近期上榜"
            if nb.get("lists"):
                detail += f"（{'、'.join(nb['lists'])}）"
            if (nb.get("abuseipdb") or {}).get("reported"):
                detail += f"；AbuseIPDB 30 天内 {nb['abuseipdb']['reported']} 个被举报"
            add("neighbours", "neighbours", "同网段邻居上榜", pts, detail)
        if nb.get("tor"):
            add("neighbours", "neighbour-tor", "同网段有 Tor 节点", 3, f"{nb['prefix']} 内有 {nb['tor']} 个 Tor 中继")
    if rep and isinstance(rep.get("ratio"), (int, float)) and rep["ratio"] >= 2:
        ratio = rep["ratio"]
        pts = 12 if ratio >= 50 else 9 if ratio >= 15 else 6 if ratio >= 5 else 3
        add("neighbours", "asn-abuse", "ASN 滥用密度偏高", pts,
            f"每万个地址 {rep['per10k']} 个近期上榜，约为全网平均的 {ratio} 倍")
    radar = asn_info.get("radar") or {}
    human_share = None
    if bot_share is not None:
        human_share = clamp(radar["human"], 0, 1) if isinstance(radar.get("human"), (int, float)) else 1 - bot_share
    bot_e = clamp((bot_share - 0.4) / 0.5, 0, 1) if bot_share is not None else 0
    bot_text = "" if bot_share is None else f"Cloudflare Radar 近 28 天：人类 {round(human_share * 100)}%，机器 {round(bot_share * 100)}%"
    if bot_e > 0:
        add("neighbours", "asn-bots", "ASN 机器流量偏高", 6 * bot_e, bot_text)
    if asn_info.get("rpki") == "invalid":
        add("neighbours", "rpki", "RPKI 校验无效", 3, "该前缀的路由宣告与 ROA 不符，可能是配置错误或劫持")

    # ---- 滥用 ----
    risk_entries = []
    for s in sources:
        if isinstance(s.get("risk"), (int, float)):
            risk_entries.append({"by": s["name"], "v": clamp(s["risk"], 0, 100),
                                 "w": (SOURCE_WEIGHTS.get(s["id"]) or {}).get("risk", 0.5)})
    risk_w = sum(e["w"] for e in risk_entries)
    risk_mean = sum(e["v"] * e["w"] for e in risk_entries) / risk_w if risk_w else None
    risk_max = max((e["v"] * min(1, e["w"]) for e in risk_entries), default=None) if risk_entries else None
    max_share = 0.4 * min(1, math.sqrt(3 / len(risk_entries))) if risk_entries else 0
    risk = js_round((1 - max_share) * risk_mean + max_share * risk_max) if risk_w else None
    risk_overlap = max(anon_any, tor["E"], 0.5 * hosting["E"])
    risk_k = 1 - 0.4 * risk_overlap
    if risk:
        add("abuse", "risk", "欺诈 / 风险分", 0.3 * risk * risk_k,
            " · ".join(f"{e['by']} {e['v']}" for e in risk_entries) +
            (f"；与代理 / 机房标记重叠，按 {pct(risk_k)} 计" if risk_k < 0.995 else ""), [asn_doubt])
    abuser = tally(flag_votes(sources, "abuser") + (extra_votes.get("abuser") or []))
    if abuser["E"] > 0:
        add("abuse", "abuser", "滥用 / 入侵记录", 10 * abuser["E"], vote_text(abuser), [label_doubt(abuser)])

    dnsbl = [d for d in (evidence.get("dnsbl") or []) if d.get("status") == "ok"]
    dnsbl_listed = [d for d in dnsbl if d.get("listed") and d.get("kind") != "tor"]
    dnsbl_pts = sum(4 if d["kind"] == "mail" else 6 for d in dnsbl_listed)
    if dnsbl_pts:
        add("abuse", "dnsbl", "黑名单收录", min(20, dnsbl_pts), "、".join(d["name"] for d in dnsbl_listed))

    lists = [x for x in (evidence.get("lists") or []) if x.get("status") == "ok"]
    attack = [x for x in lists if x.get("kind") in ("attack", "spam") and x.get("listed") and (x.get("pts") or 0) > 0]
    if attack:
        pts = max(x["pts"] for x in attack) + 2 * (len(attack) - 1)
        add("abuse", "firehol", "威胁情报列表", pts, "、".join(x["name"] for x in attack))
    otx = next((s for s in sources if s["id"] == "otx"), None)
    if otx and otx.get("pulses") and not otx.get("benign"):
        p = otx["pulses"]
        add("abuse", "otx", "威胁情报报告提及", 10 if p >= 10 else 6 if p >= 3 else 3,
            f"AlienVault OTX {p} 份报告" + (f"：{'；'.join((otx.get('pulseNames') or [])[:2])}" if otx.get("pulseNames") else ""))
    vt = next((s for s in sources if s["id"] == "virustotal"), None)
    if vt and vt.get("vtMalicious"):
        m = vt["vtMalicious"]
        add("abuse", "vt", "安全厂商标记恶意", 12 if m >= 5 else 8 if m >= 2 else 3,
            f"VirusTotal {m} 家判定恶意" + (f"、{vt.get('vtSuspicious')} 家可疑" if vt.get("vtSuspicious") else ""))
    sfs = next((s for s in sources if s["id"] == "sfs"), None)
    if sfs and (sfs.get("appears") or 0) > 0:
        recent = False
        if sfs.get("lastseen"):
            try:
                from datetime import datetime
                recent = time.time() - datetime.fromisoformat(sfs["lastseen"].replace("Z", "+00:00")).timestamp() < 90 * 86400
            except ValueError:
                recent = False
        add("abuse", "sfs", "垃圾注册记录",
            min(12, 3 + 9 * (sfs.get("confidence") or 0) / 100 + (2 if recent else 0)),
            f"StopForumSpam 记录 {sfs['appears']} 次" + (f"，最近 {sfs['lastseen'][:10]}" if sfs.get("lastseen") else ""))
    shodan = next((s for s in sources if s["id"] == "shodan"), None)
    if shodan and shodan.get("vulns"):
        cves = sorted(shodan["vulns"], reverse=True)
        add("abuse", "vulns", "存在已知漏洞", 6,
            f"{len(cves)} 个 CVE：{'、'.join(cves[:6])}{' 等' if len(cves) > 6 else ''}。Shodan 按开放端口上的软件版本推断，未实际验证；主机若被入侵，可能被用作跳板")

    # ---- 合计 ----
    categories = []
    for c in CATEGORIES:
        lst = sorted(items[c["id"]], key=lambda x: -x["pts"])
        raw = sum(x["pts"] for x in lst)
        categories.append({**c, "items": lst, "raw": r1(raw), "penalty": r1(min(c["cap"], raw))})
    penalty_of = {c["id"]: c["penalty"] for c in categories}
    ip_penalty = sum(penalty_of[k] for k in ("anon", "abuse", "neighbours", "network", "geo"))

    # ---- 加分 ----
    bonus_items = []

    def plus(bid, label, pts, detail, is_live=False, doubts=None):
        doubt = doubt_of(doubts)
        value = r1(pts * (doubt["k"] if doubt else 1))
        if value > 0.05:
            item = {"id": bid, "label": label, "pts": value, "detail": detail, "live": is_live}
            if doubt:
                item.update({"unsure": True, "full": r1(pts), "k": doubt["k"], "why": doubt["why"]})
            bonus_items.append(item)

    anon_coverage = max(anon_flags["vpn"]["of"], anon_flags["proxy"]["of"])
    if (anon_flags["vpn"]["E"] == 0 and anon_flags["proxy"]["E"] == 0 and tor["E"] == 0
            and anon_coverage >= 4 and risk is not None and risk <= 10 and len(risk_entries) >= 2):
        plus("multi-clean", "多库一致干净", 2,
             f"{anon_coverage} 个来源都未标记代理 / VPN，{len(risk_entries)} 个风险分平均 {risk}")
    if nb and nb.get("checked", 0) >= 4 and not nb.get("count") and not nb.get("whole") and not nb.get("tor"):
        plus("clean-neighbours", "邻居干净", 2, f"{nb['prefix']} 在 {nb['checked']} 个威胁列表里没有任何邻居上榜")
    if rep and isinstance(rep.get("ratio"), (int, float)) and rep["ratio"] < 0.5 and rep.get("size", 0) >= 4096:
        plus("asn-clean", "ASN 信誉优异" if rep["ratio"] <= 0.2 else "ASN 信誉良好",
             r1(2 + 2 * clamp((0.5 - rep["ratio"]) / 0.4, 0, 1)), f"滥用密度只有全网平均的 {rep['ratio']} 倍")
    safe_record = (not tor_hard and anon_any < 0.15 and abuser["E"] < 0.15 and (risk or 0) < 25
                   and not attack and not any(d.get("kind") == "abuse" for d in dnsbl_listed))
    if ip_type in ("residential", "mobile") and safe_record:
        if asn_cls in ("isp", "mobile") and asn_conf >= 0.6:
            asn_factor, asn_text = 1, "ASN 也是运营商"
        elif asn_cls in ("isp", "mobile") or not asn_cls:
            asn_factor, asn_text = 0.5, "ASN 类型未确认"
        elif asn_cls in ("business", "education", "government"):
            asn_factor, asn_text = 0.3, "ASN 不是运营商"
        else:
            asn_factor, asn_text = 0, "ASN 不是运营商"
        pts = r1(3 * clamp((home_certainty - 0.5) / 0.4, 0, 1) * asn_factor)
        if pts >= 0.3:
            plus("eyeball", "纯净移动网络" if ip_type == "mobile" else "纯净运营商 IP", pts,
                 f"类型确定度 {round(home_certainty * 100)}%，{asn_text}，没有匿名或滥用记录；网站很少整段封禁这类地址",
                 False, [type_doubt])
    if native and native_certainty >= 0.7:
        plus("native", "原生 IP", 0.5, "注册地与定位一致")
    if asn_info.get("rpki") == "valid":
        plus("rpki", "RPKI 有效", 0.5, "路由宣告有 ROA 背书，不像被劫持的地址")
    greynoise = next((s for s in sources if s["id"] == "greynoise"), None)
    if greynoise and greynoise.get("riot"):
        plus("riot", "已知良性服务", 1, f"GreyNoise RIOT：{greynoise.get('name') or '常见商业服务'}")
    if bot_share is not None and bot_share <= 0.2:
        plus("asn-human", "人类流量为主", 1, bot_text)
    sharing = sharing_of(seen, devices, anon_any >= 0.5 or tor["E"] >= 0.5 or anon_flags["relay"]["E"] >= 0.5 or ip_type == "mobile")
    if sharing["low"]:
        plus("sharers", "疑似独享" if sharing["tier"] == "疑似独享" else "共享人数少", 2,
             f"Proxycheck 估计该地址约 {sharing['address']} 台设备、同网段约 {sharing['subnet']} 台；本次没有取到本站检测记录")
    ip_bonus = min(BONUS_CAP, sum(b["pts"] for b in bonus_items if not b["live"]))
    all_bonus = min(BONUS_CAP, sum(b["pts"] for b in bonus_items))

    ip_score = js_round(clamp(BASE + ip_bonus - ip_penalty, 0, 100))
    total = ip_score  # 非自查：live 分类为空，total == ipScore
    if tor_hard:
        ip_score = min(ip_score, 25)
        total = min(total, 25)
    grade = grade_of(total)
    scored_sources = len(sources)
    anon_of = max(anon_flags["vpn"]["of"], anon_flags["proxy"]["of"])
    confidence = ("high" if scored_sources >= 10 and anon_of >= 3
                  else "medium" if scored_sources >= 5 and anon_of >= 2 else "low")
    return {
        "score": total, "ipScore": ip_score, "base": BASE,
        "bonus": {"items": sorted(bonus_items, key=lambda x: -x["pts"]), "total": r1(all_bonus), "ip": r1(ip_bonus), "cap": BONUS_CAP},
        "grade": grade, "categories": categories, "notes": notes,
        "asnTrust": ({**asn_trust, "label": asn_info.get("label"), "applied": bool(asn_doubt)} if asn_trust else None),
        "summary": {"country": country, "city": city, "asn": asn, "org": (org_rank[0]["value"] if org_rank else None),
                    "hostname": hostname, "type": ip_type, "regCountry": reg_country, "native": native,
                    "ipTimezone": ip_tz},
        "checks": {
            "type": {"value": ip_type, "from": type_from, "hosting": hosting, "mix": type_mix,
                     "certainty": r1(type_certainty * 100) / 100},
            "native": {"native": native, "regCountry": reg_country, "share": native_share,
                       "certainty": r1(native_certainty * 100) / 100},
            "lease": lease,
            "geo": {"country": country, "city": city, "support": country_support, "countries": countries,
                    "count": geo_count},
            "anon": {"vpn": anon_flags["vpn"], "proxy": anon_flags["proxy"], "relay": anon_flags["relay"],
                     "crawler": anon_flags["crawler"], "E": anon_any},
            "tor": tor,
            "risk": {"value": risk, "entries": risk_entries},
            "abuse": {"abuser": abuser, "lists": [x["name"] for x in attack],
                      "listsChecked": len([x for x in lists if x.get("kind") in ("attack", "spam")]),
                      "listed": [x["name"] for x in lists if x.get("kind") in ("attack", "spam") and x.get("listed")],
                      "otx": {"pulses": (otx or {}).get("pulses", 0), "benign": bool((otx or {}).get("benign"))} if otx else None,
                      "sfs": {"appears": (sfs or {}).get("appears", 0), "lastseen": (sfs or {}).get("lastseen")} if sfs else None},
            "dnsbl": {"listed": [d["name"] for d in dnsbl_listed],
                      "checked": len([d for d in dnsbl if d.get("kind") != "tor"])},
            "neighbours": dict(nb) if nb else None,
            "asnRep": dict(rep) if rep else None,
            "bots": {"bot": r3(bot_share) if bot_share is not None else None,
                     "human": r3(human_share) if human_share is not None else None},
            "asn": {"consistency": asn_consistency, "inferred": (asn_info.get("inferred") or {}),
                    "label": asn_info.get("label")},
            "sharers": sharing,
            "ports": {"ports": (shodan or {}).get("ports") or [], "tags": (shodan or {}).get("tags") or [],
                      "vulns": len((shodan or {}).get("vulns") or [])},
        },
        "confidence": {"level": confidence, "sources": scored_sources, "anonSources": anon_of},
    }

# ---------------- 编排（main.js startRun 移植，非自查路径） ----------------

_health = {"value": None, "at": 0}

def get_health(force=False):
    if not force and _health["value"] and time.time() - _health["at"] < 60:
        return _health["value"]
    for timeout in (6, 10):
        r = get_json(f"{API_BASE}/health", timeout=timeout, pace=True)
        if r["ok"] and (r["data"] or {}).get("service") == "egress-observatory-api":
            routes = r["data"].get("routes") or r["data"].get("providers")
            if isinstance(routes, list):
                _health["value"] = {**r["data"], "routes": routes}
                _health["at"] = time.time()
                return _health["value"]
        if r["status"] == 429:
            break
    return None

def check_ip(ip, verbose=False):
    addr = parse_ip(ip)
    if addr is None:
        raise ValueError(f"无效 IP：{ip}")
    health = get_health(force=True)
    ctx = {"health": health, "results": {}}
    run = {"ip": str(addr), "v": addr.version, "sources": {}, "dnsbl": [], "lists": [],
           "asn": None, "asnRep": None}
    # ---- 来源（并发；ipapimirror 需等 ipapi 结果，第二阶段跑） ----
    def run_one(item):
        sid, name, fn = item
        if fn is None:
            return sid, {"status": "skip", "error": "未配置密钥"}
        try:
            return sid, {"status": "ok", "data": fn(str(addr), ctx)}
        except SourceFail as e:
            return sid, {"status": "error", "error": str(e)}
        except Exception as e:
            return sid, {"status": "error", "error": f"请求失败：{str(e)[:100]}"}
    phase1 = [s for s in SOURCES if s[0] != "ipapimirror"]
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for sid, rec in ex.map(run_one, phase1):
            run["sources"][sid] = rec
            ctx["results"][sid] = rec
    run["sources"]["ipapimirror"] = run_one(next(s for s in SOURCES if s[0] == "ipapimirror"))[1]
    ctx["results"]["ipapimirror"] = run["sources"]["ipapimirror"]

    # ---- IPOK 补充 ----
    try:
        ipok_rows = lookup_ipok(str(addr))
    except SourceFail as e:
        ipok_rows = {}
        if verbose:
            print(f"  [IPOK 失败：{e}]", file=sys.stderr)
    for sid, row in ipok_rows.items():
        if row.get("unavailable"):
            continue
        rec = run["sources"].get(sid) or {"status": "skip", "error": "未配置密钥"}
        extra = {**(row.get("fields") or {}), "flags": row.get("flags") or {},
                 "risk": row.get("percent"), "webRiskScore": row.get("percent"),
                 "webObservedAt": row.get("observedAt")}
        run["sources"][sid] = fill_source(rec, extra, "IPOK 逐库风险与匿名标记" +
                                          (f" · {row.get('observedAt')}" if row.get("observedAt") else ""))
    # ---- ipinfo ← AbuseIPDB usageType；dbip ← Net Atlas ----
    abuse = (run["sources"].get("abuseipdb") or {}).get("data") or {}
    ipinfo_rec = run["sources"].get("ipinfo") or {}
    if not (ipinfo_rec.get("data") or {}).get("usageType") and abuse.get("usageType"):
        run["sources"]["ipinfo"] = fill_source(
            ipinfo_rec, {"usageType": abuse["usageType"], "type": (ipinfo_rec.get("data") or {}).get("type") or abuse["usageType"]},
            "AbuseIPDB")
    atlas = (run["sources"].get("netatlas") or {}).get("data") or {}
    if atlas.get("locationDatabase") == "DB-IP City Lite":
        run["sources"]["dbip"] = fill_source(
            run["sources"].get("dbip") or {"status": "error"},
            {"country": atlas.get("country"), "city": atlas.get("city"), "region": atlas.get("region")},
            "DB-IP City Lite，经 Net Atlas 转供")

    # ---- DNSBL + CIDR 列表（并发） ----
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        run["dnsbl"] = list(ex.map(lambda l: check_dnsbl(l, str(addr)), DNSBLS))
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        run["lists"] = list(ex.map(lambda l: check_cidr_list(l, str(addr)), CIDR_LISTS))

    # ---- ASN 画像 ----
    def src_data(sid):
        rec = run["sources"].get(sid) or {}
        return rec.get("data") if rec.get("status") == "ok" else None
    asn_num = None
    for sid in ("ripeprefix", "ipguide", "ipinfo", "proxycheck", "ipwhois", "ipsb", "ipleak", "geojs", "netatlas"):
        d = src_data(sid)
        if d and d.get("asn"):
            asn_num = d["asn"]
            break
    prefix = None
    for sid in ("ripeprefix", "ipguide", "netatlas"):
        d = src_data(sid)
        if d and d.get("prefix"):
            prefix = d["prefix"]
            break
    if asn_num:
        try:
            run["asn"] = fetch_asn(asn_num, prefix, health)
            if run["asn"].get("routes"):
                run["asnRep"] = asn_abuse_density(run["asn"]["routes"])
        except Exception as e:
            if verbose:
                print(f"  [ASN 画像失败：{e}]", file=sys.stderr)
    evidence = build_evidence(run)
    result = score(evidence)
    result["sourcesStatus"] = {sid: {"status": rec.get("status"), "error": rec.get("error")}
                               for sid, rec in run["sources"].items()}
    result["dnsblStatus"] = {"checked": len([d for d in run["dnsbl"] if d.get("status") == "ok"]),
                             "errors": len([d for d in run["dnsbl"] if d.get("status") == "error"])}
    result["listsStatus"] = {"checked": len([x for x in run["lists"] if x.get("status") == "ok"]),
                             "errors": len([x for x in run["lists"] if x.get("status") == "error"])}
    result["asn"] = run["asn"]
    return result

# ---------------- CLI ----------------

def fmt_report(ip, res):
    g = res["grade"]
    lines = [f"{ip}: {res['score']} 分 / {g['letter']} 级（{g['label']}）  [基准 {res['base']} + 加分 {res['bonus']['ip']} − 扣分]",
             f"  置信度：{res['confidence']['level']}（{res['confidence']['sources']} 个来源 ok）",
             f"  摘要：{res['summary'].get('country')} {res['summary'].get('city') or ''} · "
             f"AS{res['summary'].get('asn')} {res['summary'].get('org') or ''} · "
             f"类型 {TYPE_LABEL.get(res['summary'].get('type'), res['summary'].get('type'))} · "
             f"{'原生' if res['summary'].get('native') else ('广播' if res['summary'].get('native') is False else '原生未知')}"]
    for c in res["categories"]:
        if not c["items"] and c["penalty"] == 0:
            continue
        lines.append(f"  [{c['label']} −{c['penalty']}（上限 {c['cap']}）]")
        for it in c["items"]:
            mark = " ?" if it.get("unsure") else ""
            lines.append(f"    −{it['pts']}{mark} {it['label']}：{it['detail']}" + (f"（{it['why']}）" if it.get("why") else ""))
    if res["bonus"]["items"]:
        lines.append(f"  [加分 +{res['bonus']['ip']}（上限 {res['bonus']['cap']}）]")
        for b in res["bonus"]["items"]:
            lines.append(f"    +{b['pts']} {b['label']}：{b['detail']}")
    ch = res["checks"]
    risk = ch["risk"]
    lines.append("  关键信号："
                 f"欺诈分 {risk['value']}（{', '.join(f'{e['by']} {e['v']}' for e in risk['entries'])}）" if risk["value"] is not None else "  关键信号：欺诈分 无数据")
    lines.append(f"    VPN {ch['anon']['vpn']['yes']}/{ch['anon']['vpn']['of']}（E={ch['anon']['vpn']['E']}）· "
                 f"代理 {ch['anon']['proxy']['yes']}/{ch['anon']['proxy']['of']}（E={ch['anon']['proxy']['E']}）· "
                 f"Tor E={ch['tor']['E']} · 机房 {ch['type']['hosting']['yes']}/{ch['type']['hosting']['of']}（E={ch['type']['hosting']['E']}）")
    lines.append(f"    黑名单：{', '.join(ch['dnsbl']['listed']) or '0 收录'}（查了 {ch['dnsbl']['checked']} 个）· "
                 f"威胁列表：{', '.join(ch['abuse']['listed']) or '无'} · "
                 f"OTX {((ch['abuse'].get('otx') or {}).get('pulses'))} 份 · "
                 f"SFS {((ch['abuse'].get('sfs') or {}).get('appears'))} 次 · "
                 f"漏洞 {ch['ports']['vulns']} 个")
    nb = ch["neighbours"]
    if nb:
        lines.append(f"    邻居：{nb.get('prefix')} 内 {nb.get('count', 0)} 个上榜（查了 {nb.get('checked', 0)} 个列表）"
                     + (f"，整段上榜：{', '.join(nb.get('whole') or [])}" if nb.get("whole") else ""))
    rep = ch["asnRep"]
    if rep:
        lines.append(f"    ASN 滥用密度：{rep.get('per10k')}/万，约为全网平均的 {rep.get('ratio')} 倍")
    if ch["bots"]["bot"] is not None:
        lines.append(f"    ASN 机器流量：{round(ch['bots']['bot'] * 100)}%")
    if ch["lease"]:
        lines.append(f"    租赁：{'是' if ch['lease'].get('leased') else ('可能' if ch['lease'].get('possible') else '否')} "
                     f"（把握 {ch['lease'].get('confidence')}）：{'; '.join(ch['lease'].get('reasons') or [])}")
    failed = [f"{sid}（{r['error'] or r['status']}）" for sid, r in res["sourcesStatus"].items() if r["status"] != "ok"]
    if failed:
        lines.append(f"  未拿到数据的来源（{len(failed)}）：{'; '.join(failed)}")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="egress-observatory 评分复刻（只读）")
    ap.add_argument("target", nargs="?", help="单个 IP，或 --batch 时的 IP 列表文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--batch", action="store_true", help="批量模式：文件每行 'IP [期望分 期望级]'")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if not args.target:
        ap.print_help()
        return 2
    if args.batch:
        rows = []
        with open(args.target, encoding="utf-8") as f:
            for line in f:
                parts = line.replace(",", " ").split()
                if not parts or parts[0].startswith("#"):
                    continue
                rows.append(parts)
        print(f"{'IP':<18}{'复刻':<10}{'期望':<10}{'偏差':<8}结论")
        for parts in rows:
            ip = parts[0]
            try:
                res = check_ip(ip, verbose=args.verbose)
            except Exception as e:
                print(f"{ip:<18}失败：{e}")
                continue
            got = f"{res['score']}/{res['grade']['letter']}"
            if len(parts) >= 3:
                exp_score, exp_grade = int(parts[1]), parts[2]
                diff = res["score"] - exp_score
                verdict = "✓ 等级一致" if res["grade"]["letter"] == exp_grade else "✗ 等级不同"
                print(f"{ip:<18}{got:<10}{exp_score}/{exp_grade:<8}{diff:+d}{'':<7}{verdict}")
            else:
                print(f"{ip:<18}{got}")
            if args.verbose:
                print(fmt_report(ip, res))
                print()
        return 0
    res = check_ip(args.target, verbose=args.verbose)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2, default=str))
    else:
        print(fmt_report(args.target, res))
    return 0

if __name__ == "__main__":
    sys.exit(main())

# NOTES（与页面版的已知偏差，验证时对照）：
# 1. 网页补充未复刻：IPSuper / IPinfo 网页 / Chrome 插件三路补充（/v1/page/*）当前服务不可用
#    （2026-11-19 实测 page-service-unavailable）。浏览器实测时若拿到了补充数据，其 IPinfo 隐私
#    标记（权重最高 1.3/1.6）与 IPSuper 类型/风险会影响分数；本脚本缺这部分，分数可能系统性偏高。
# 2. 未调 /v1/seen：共享人数扣分（>10 人才扣）与“疑似独享”加分里的本站记录缺失；对冷门 IP 影响极小。
# 3. 未做连接实测：WebRTC/DNS/时区/验证码等仅对“本机出口”有意义；查远端 IP 时页面也不做。
# 4. 场景分与 verdict 未复刻：不影响总分。
# 5. 数据时效：FireHOL/DNSBL/各库每天都在变；浏览器实测（21:00）与本脚本运行时间不同，个别信号
#    （如 dbip 额度、ip2location 限流）可能不同，导致几分偏差。
# 6. 本机 VM 出站经代理：部分上游（尤其 RDAP / PeeringDB / RIPEstat）在 GCP 上复核结论可能不同。
