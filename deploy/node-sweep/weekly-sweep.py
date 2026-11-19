#!/usr/bin/env python3
"""Weekly free-node sweep for m-ui (GCP, systemd timer).

Pipeline (one run = one "round", same rules as manual rounds 1-4):
  1. download fresh free18 subscription (jsDelivr, daily refresh)
  2. parse -> candidate IPs (literal IPv4, <=2 nodes/IP, exclude tested IPs,
     exclude tls=false + xtls-rprx-vision nodes: 4/4 handshake failures in round 4)
  3. ASN screen via ip-api.com (hosting/proxy flags) -> ISP-like pool
  4. shortlist 14 (ISP-like first, one per ASN for diversity)
  5. egress-observatory scoring (local replica egress_score.py); drop D/F (<55)
  6. IPPure retest (ippure.py); drop coefficient >= 80. If IPPure is down,
     degrade to egress-only (never abort the whole run on it).
  7. generate share links (vless/vmess, URL-encoded fragments)
  8. m-ui cleanup: 0-user ext entries outside the keep-list get speed-tested;
     delete only when every resolved cell is fail. Entries with users are
     never touched. Keep-list: 德国 (self-built cloady backup), 宝可梦机场.
  9. import passers as ext type=link (skip server IPs already present;
     name collisions get a date suffix), speed-test each, delete fail ones.
 10. write status.json + last-run.json for the Xiaotu Feishu notifier.

Layout on GCP (all under /root/node-sweep/):
  weekly-sweep.py, egress_score.py, ippure.py, credentials (600, MUI_USER/MUI_PASS),
  tested-ips.json (seeded with rounds 1-4), status.json, last-run.json, sweep.log

Flags: --dry-run (no m-ui mutations), --skip-mui (pipeline only, no panel calls),
       --no-cleanup (skip step 8). Exit 0 = run finished (even with 0 survivors);
       exit 1 = fatal (no subscription, egress totally down, m-ui login failed).
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SUB_URL = "https://cdn.jsdelivr.net/gh/free18/v2ray@main/c.yaml"
IPAPI_FIELDS = "status,country,countryCode,isp,org,as,asname,mobile,proxy,hosting,query"
SHORTLIST_N = 14
EGRESS_MIN_SCORE = 55          # D/F eliminated (grade < C)
IPPURE_MAX_COEF = 80           # >= 80 eliminated (extreme risk)
KEEP_EXTS = {"德国", "宝可梦机场"}
MUI_LOCAL = "https://127.0.0.1:2053/app/api"
MUI_PUBLIC = "https://panel.hqyyk.de5.net/app/api"
TEST_POLL_INTERVAL = 2
TEST_POLL_TIMEOUT = 300

CRED_PATH = os.path.join(HERE, "credentials")
TESTED_PATH = os.path.join(HERE, "tested-ips.json")
STATUS_PATH = os.path.join(HERE, "status.json")
LASTRUN_PATH = os.path.join(HERE, "last-run.json")
LOG_PATH = os.path.join(HERE, "sweep.log")


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ---------------------------------------------------------------- subscription
def download_subscription():
    req = urllib.request.Request(SUB_URL, headers={"User-Agent": "curl/8"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            log(f"subscription downloaded: {len(data)} bytes")
            return data.decode("utf-8", errors="replace")
        except Exception as e:
            log(f"subscription download attempt {attempt + 1} failed: {e}")
            time.sleep(5)
    raise RuntimeError("subscription download failed after 3 attempts")


def parse_proxies(text):
    try:
        import yaml
    except ImportError:
        raise RuntimeError("PyYAML missing: apt install python3-yaml")
    doc = yaml.safe_load(text)
    proxies = doc.get("proxies", []) if isinstance(doc, dict) else []
    log(f"subscription nodes: {len(proxies)}")
    return proxies


def build_candidates(proxies, tested):
    """Same filters as rounds 1-4, plus the round-4 vision lesson."""
    by_ip = defaultdict(list)
    for p in proxies:
        srv = str(p.get("server", ""))
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", srv):
            continue
        by_ip[srv].append(p)
    candidates = []
    skipped_vision = 0
    for ip, nodes in by_ip.items():
        if ip in tested or len(nodes) > 2:
            continue
        node = nodes[0]
        # tls=false + xtls-rprx-vision: 4/4 handshake failures in round 4
        if not node.get("tls") and node.get("flow") == "xtls-rprx-vision":
            skipped_vision += 1
            continue
        if node.get("type") not in ("vless", "vmess", "trojan"):
            continue
        candidates.append({"ip": ip, "node": node, "count": len(nodes)})
    log(f"candidates: {len(candidates)} (skipped {skipped_vision} tls-off vision nodes)")
    return candidates


# ---------------------------------------------------------------- ASN screen
def asn_screen(ips):
    """ip-api.com single GETs, 1.4s apart (free 45/min). Resume-safe per run."""
    out = {}
    for n, ip in enumerate(ips, 1):
        rec = None
        for _ in range(2):
            try:
                req = urllib.request.Request(
                    f"http://ip-api.com/json/{ip}?fields={IPAPI_FIELDS}",
                    headers={"User-Agent": "curl/8"},
                )
                with urllib.request.urlopen(req, timeout=20) as resp:
                    rec = json.load(resp)
                break
            except Exception as e:
                log(f"ip-api {ip}: {e}")
                time.sleep(3)
        out[ip] = rec if rec and rec.get("status") == "success" else {"status": "failed", "query": ip}
        if n % 50 == 0 or n == len(ips):
            log(f"ASN screen progress: {n}/{len(ips)}")
        time.sleep(1.4)
    ok = sum(1 for r in out.values() if r.get("status") == "success")
    isp_like = [ip for ip, r in out.items()
                if r.get("status") == "success" and not r.get("hosting") and not r.get("proxy")]
    log(f"ASN screen: {ok}/{len(ips)} ok, ISP-like: {len(isp_like)}")
    return out, isp_like


def pick_shortlist(candidates, asn, isp_like):
    """ISP-like first, one per ASN for diversity, then fill to SHORTLIST_N."""
    cand = {c["ip"]: c for c in candidates}
    isp_set = set(isp_like)
    # pass 1: one per ASN from ISP-like pool, prefer mobile/eyeball-ish first
    def sort_key(ip):
        r = asn.get(ip, {})
        return (0 if r.get("mobile") else 1, r.get("countryCode", "ZZ"), ip)
    ordered = sorted(isp_set, key=sort_key)
    picks, seen_asn = [], set()
    for ip in ordered:
        a = asn.get(ip, {}).get("as", "?")
        if a in seen_asn:
            continue
        seen_asn.add(a)
        picks.append(ip)
        if len(picks) >= SHORTLIST_N:
            break
    # pass 2: second IP per ASN from ISP-like pool
    if len(picks) < SHORTLIST_N:
        for ip in ordered:
            if ip not in picks:
                picks.append(ip)
                if len(picks) >= SHORTLIST_N:
                    break
    # pass 3: fill from the rest (non-ISP pool), ASN-diverse
    if len(picks) < SHORTLIST_N:
        rest = sorted((c["ip"] for c in candidates if c["ip"] not in isp_set),
                      key=lambda ip: asn.get(ip, {}).get("as", "?"))
        for ip in rest:
            a = asn.get(ip, {}).get("as", "?")
            if a in seen_asn:
                continue
            seen_asn.add(a)
            picks.append(ip)
            if len(picks) >= SHORTLIST_N:
                break
    shortlist = []
    for ip in picks:
        node = cand[ip]["node"]
        a = asn.get(ip, {})
        shortlist.append({
            "ip": ip, "port": str(node.get("port")), "type": node.get("type"),
            "name": node.get("name"), "country": a.get("countryCode", "?"),
            "country_name": a.get("country", ""),
            "asn": a.get("as", "?"), "isp": a.get("isp", "?"),
        })
    log(f"shortlist: {len(shortlist)} IPs")
    for s in shortlist:
        log(f"  {s['ip']}:{s['port']} {s['type']} {s['country']} {s['asn']} | {s['name']}")
    return shortlist


# ---------------------------------------------------------------- scoring
def egress_scores(ips):
    """Score via the local egress-observatory replica (one process, shared caches)."""
    try:
        import egress_score
    except ImportError as e:
        raise RuntimeError(f"egress_score.py not importable: {e}")
    out = {}
    for ip in ips:
        try:
            res = egress_score.check_ip(ip)
            out[ip] = {"score": res["score"], "grade": res["grade"]["letter"]}
            log(f"egress {ip}: {res['score']}/{res['grade']['letter']}")
        except Exception as e:
            log(f"egress {ip}: FAILED ({e})")
            out[ip] = {"score": None, "grade": None, "error": str(e)}
    return out


def ippure_scores(ips):
    """IPPure coefficients via one persistent signed client. Returns (results, ok)."""
    try:
        import ippure as ippure_mod
    except ImportError as e:
        log(f"IPPure unavailable (import failed: {e}); degrading to egress-only")
        return {}, False
    client = ippure_mod.IPPureClient()
    out, any_ok = {}, False
    try:
        for ip in ips:
            try:
                coef = client.risk(ip)
                out[ip] = {"coef": coef}
                any_ok = True
                log(f"ippure {ip}: {coef}%")
            except Exception as e:
                log(f"ippure {ip}: FAILED ({e})")
                out[ip] = {"coef": None, "error": str(e)}
    finally:
        client.close()
    if not any_ok:
        log("IPPure fully failed; degrading to egress-only")
    return out, any_ok


# ---------------------------------------------------------------- share links
def vless_link(p):
    q = {"encryption": "none"}
    q["security"] = "tls" if p.get("tls") else "none"
    sni = p.get("servername") or p.get("sni")
    if sni:
        q["sni"] = sni
    if p.get("client-fingerprint"):
        q["fp"] = p["client-fingerprint"]
    net = p.get("network") or "tcp"
    q["type"] = net
    if p.get("flow"):
        q["flow"] = p["flow"]
    if net == "ws":
        ws = p.get("ws-opts") or {}
        if ws.get("path"):
            q["path"] = ws["path"]
        host = (ws.get("headers") or {}).get("Host")
        if host:
            q["host"] = host
    if p.get("alpn"):
        q["alpn"] = ",".join(p["alpn"])
    qs = urllib.parse.urlencode(q, safe="")
    frag = urllib.parse.quote(p["name"], safe="")
    return f"vless://{p['uuid']}@{p['server']}:{p['port']}?{qs}#{frag}"


def vmess_link(p):
    net = p.get("network") or "tcp"
    ws = p.get("ws-opts") or {} if net == "ws" else {}
    obj = {
        "v": "2", "ps": p["name"], "add": str(p["server"]), "port": str(p["port"]),
        "id": p["uuid"], "aid": str(p.get("alterId", 0)), "scy": p.get("cipher", "auto"),
        "net": net, "type": "none",
        "host": (ws.get("headers") or {}).get("Host", ""), "path": ws.get("path", ""),
        "tls": "tls" if p.get("tls") else "",
        "sni": p.get("servername") or p.get("sni") or "", "alpn": "",
    }
    raw = json.dumps(obj, ensure_ascii=False, separators=(", ", ": ")).encode("utf-8")
    return "vmess://" + base64.b64encode(raw).decode()


def trojan_link(p):
    q = {}
    sni = p.get("servername") or p.get("sni")
    if sni:
        q["sni"] = sni
    if p.get("flow"):
        q["flow"] = p["flow"]
    net = p.get("network") or "tcp"
    q["type"] = net
    if net == "ws":
        ws = p.get("ws-opts") or {}
        if ws.get("path"):
            q["path"] = ws["path"]
        host = (ws.get("headers") or {}).get("Host")
        if host:
            q["host"] = host
    qs = urllib.parse.urlencode(q, safe="")
    frag = urllib.parse.quote(p["name"], safe="")
    base = f"trojan://{p['password']}@{p['server']}:{p['port']}"
    return f"{base}?{qs}#{frag}" if qs else f"{base}#{frag}"


def normalize_name(item, used):
    """Name weekly nodes so they land in the 其他 group tab.

    Rule (user-set): self-built nodes have no tab and live in GLOBAL only;
    every other node belongs to a tab. The 其他 tab's filter is
    '^[A-Z]{2}-[A-Z]', so weekly nodes get 'CC-EnglishCountry' names
    (e.g. SG-Singapore, CY-Cyprus (2)). Falls back to the original name
    when the country is unknown (stays in GLOBAL only).
    """
    cc = item.get("country", "?")
    cn = (item.get("country_name") or "").strip()
    if len(cc) != 2 or not cc.isalpha() or not cn:
        return item["name"]
    base = f"{cc.upper()}-{cn}"
    name, n = base, 2
    while name in used:
        name = f"{base} ({n})"
        n += 1
    used.add(name)
    return name


def build_link(node):
    t = node.get("type")
    if t == "vless":
        return vless_link(node)
    if t == "vmess":
        return vmess_link(node)
    if t == "trojan":
        return trojan_link(node)
    raise ValueError(f"unsupported node type {t}")


def link_server_ip(link):
    """Extract the server IP from a share link (for duplicate detection)."""
    try:
        if link.startswith("vmess://"):
            obj = json.loads(base64.b64decode(link[len("vmess://"):]))
            return str(obj.get("add", ""))
        m = re.match(r"(?:vless|trojan)://[^@]+@([^:/?#]+)", link)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ---------------------------------------------------------------- m-ui client
def totp_code(secret, window=0):
    """RFC 6238 TOTP (SHA1, 30s step, 6 digits). Secret is base32."""
    key = base64.b32decode(secret.strip().upper())
    counter = int(time.time()) // 30 + window
    msg = struct.pack(">Q", counter)
    digest = hmac_mod.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def load_credentials():
    creds = {}
    try:
        with open(CRED_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip()
    except OSError:
        pass
    return creds


class MuiError(Exception):
    pass


class TotpRequired(MuiError):
    pass


class MuiClient:
    def __init__(self):
        self.base = None
        self.cookie = None
        self._unverified = ssl._create_unverified_context()

    def _request(self, method, path, body=None, use_cookie=True, timeout=30):
        last_err = None
        for base in ([self.base] if self.base else [MUI_LOCAL, MUI_PUBLIC]):
            url = base + path
            headers = {"Content-Type": "application/json"}
            if use_cookie and self.cookie:
                headers["Cookie"] = self.cookie
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            # localhost first tries verified TLS, then unverified (cert may be
            # self-signed or issued for the public name); public base stays verified.
            contexts = [None]
            if "127.0.0.1" in base:
                contexts.append(self._unverified)
            for ctx in contexts:
                try:
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                        self.base = base
                        return resp.status, resp.read(), resp.headers
                except urllib.error.HTTPError as e:
                    self.base = base
                    return e.code, e.read(), e.headers
                except (ssl.SSLError, urllib.error.URLError) as e:
                    last_err = e
                    continue
        raise MuiError(f"request {method} {path} failed: {last_err}")

    def login(self, user, password, totp_seed=None):
        payload = {"username": user, "password": password}
        status, raw, headers = self._request("POST", "/login", payload, use_cookie=False)
        try:
            data = json.loads(raw)
        except ValueError:
            data = {}
        if status == 200:
            self._store_cookie(headers)
            return
        if data.get("needCode") or data.get("totp"):
            if not totp_seed:
                raise TotpRequired("panel TOTP is enabled but no MUI_TOTP_SEED in credentials")
            for window in (0, -1):
                payload["code"] = totp_code(totp_seed, window)
                status, raw, headers = self._request("POST", "/login", payload, use_cookie=False)
                if status == 200:
                    self._store_cookie(headers)
                    return
            raise MuiError("TOTP code rejected")
        raise MuiError(f"login failed ({status}): {data.get('error', raw[:200])}")

    def _store_cookie(self, headers):
        set_cookie = headers.get("Set-Cookie", "")
        m = re.search(r"m-ui-session=[^;]+", set_cookie)
        if not m:
            raise MuiError("login ok but no m-ui-session cookie returned")
        self.cookie = m.group(0)

    def logout(self):
        try:
            self._request("POST", "/logout", {})
        except MuiError:
            pass

    def list_exts(self):
        status, raw, _ = self._request("GET", "/exts")
        if status != 200:
            raise MuiError(f"GET /exts failed ({status}): {raw[:200]}")
        return json.loads(raw)

    def create_ext(self, name, link):
        payload = {"name": name, "type": "link", "value": link,
                   "prefix": "", "exclude": "", "remark": "",
                   "sort": 0, "enabled": True}
        status, raw, _ = self._request("POST", "/exts", payload)
        if status != 200:
            raise MuiError(f"create ext {name} failed ({status}): {raw[:200]}")
        return json.loads(raw)

    def delete_ext(self, ext_id):
        status, raw, _ = self._request("DELETE", f"/exts/{ext_id}")
        if status != 200:
            raise MuiError(f"delete ext {ext_id} failed ({status}): {raw[:200]}")

    def ext_nodes(self, ext_id):
        status, raw, _ = self._request("GET", f"/exts/{ext_id}/nodes")
        if status != 200:
            raise MuiError(f"GET /exts/{ext_id}/nodes failed ({status}): {raw[:200]}")
        return json.loads(raw)

    def test_ext(self, ext_id, timeout=TEST_POLL_TIMEOUT):
        """Speed-test one ext (all its output nodes), return {nodeKey: cell} for the local server."""
        nodes = self.ext_nodes(ext_id)
        local_ids = {str(s["id"]) for s in nodes.get("servers", []) if s.get("isLocal")}
        if not local_ids:
            local_ids = {str(s["id"]) for s in nodes.get("servers", [])}
        status, raw, _ = self._request("POST", f"/exts/{ext_id}/nodes/test", {})
        if status != 200:
            raise MuiError(f"start test ext {ext_id} failed ({status}): {raw[:200]}")
        job = json.loads(raw).get("job")
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            time.sleep(TEST_POLL_INTERVAL)
            try:
                status, raw, _ = self._request("GET", f"/exts/{ext_id}/nodes/test/{job}")
            except MuiError as e:
                raise MuiError(f"poll test {job}: {e}")
            if status == 404:
                raise MuiError(f"test job {job} lost (panel restarted?)")
            if status != 200:
                raise MuiError(f"poll test {job} failed ({status})")
            last = json.loads(raw)
            if last.get("done"):
                break
        if not last or not last.get("done"):
            raise MuiError(f"test job {job} timed out after {timeout}s")
        cells = {}
        for key, by_server in (last.get("results") or {}).items():
            for sid, cell in by_server.items():
                if sid in local_ids:
                    cells[key] = cell
        return cells


# ---------------------------------------------------------------- sweep logic
def test_cells_verdict(cells):
    """ok -> alive; all fail -> dead; anything untestable -> unknown (keep)."""
    states = [c.get("state") for c in cells.values()]
    if not states:
        return "unknown", None
    if any(s == "ok" for s in states):
        delay = min((c.get("delayMs") for c in cells.values()
                     if c.get("state") == "ok" and c.get("delayMs") is not None),
                    default=None)
        return "alive", delay
    if all(s == "fail" for s in states):
        return "dead", None
    return "unknown", None


def cleanup_exts(mui, dry_run):
    """Pre-import cleanup: test 0-user exts outside the keep-list; delete all-fail ones."""
    deleted, kept, errors = [], [], []
    exts = mui.list_exts()
    for ext in exts:
        name = ext.get("name", "")
        if name in KEEP_EXTS:
            continue
        if (ext.get("userCount") or 0) > 0:
            continue
        ext_id = ext["id"]
        log(f"cleanup: testing 0-user ext '{name}' (id {ext_id})")
        if dry_run:
            # dry-run still validates the read-only nodes endpoint shape
            try:
                nodes = mui.ext_nodes(ext_id)
                servers = [s.get("id") for s in nodes.get("servers", [])]
                log(f"cleanup (dry-run): '{name}' nodes endpoint ok, servers={servers}")
            except MuiError as e:
                errors.append({"name": name, "id": ext_id, "error": f"nodes probe: {e}"})
                log(f"cleanup (dry-run): '{name}' nodes probe failed: {e}")
            kept.append({"name": name, "id": ext_id, "note": "dry-run, skipped"})
            continue
        try:
            cells = mui.test_ext(ext_id)
        except MuiError as e:
            errors.append({"name": name, "id": ext_id, "error": str(e)})
            log(f"cleanup: '{name}' test error: {e} (kept)")
            continue
        verdict, delay = test_cells_verdict(cells)
        if verdict == "dead":
            # re-verify id->name before deleting
            current = {e["id"]: e.get("name") for e in mui.list_exts()}
            if current.get(ext_id) != name:
                errors.append({"name": name, "id": ext_id,
                               "error": "id/name mismatch on re-check, not deleted"})
                log(f"cleanup: '{name}' id/name mismatch on re-check, NOT deleted")
                continue
            mui.delete_ext(ext_id)
            deleted.append({"name": name, "id": ext_id})
            log(f"cleanup: deleted dead ext '{name}' (id {ext_id})")
        else:
            kept.append({"name": name, "id": ext_id, "verdict": verdict, "delayMs": delay})
            log(f"cleanup: kept '{name}' ({verdict})")
    return {"deleted": deleted, "kept": kept, "errors": errors}


def import_and_test(mui, links, dry_run):
    """Import passers, speed-test each, delete the dead. Returns outcome lists."""
    exts = mui.list_exts()
    existing_names = {e.get("name") for e in exts}
    existing_ips = set()
    for e in exts:
        if e.get("type") == "link" and e.get("value"):
            ip = link_server_ip(e["value"])
            if ip:
                existing_ips.add(ip)
    today = time.strftime("%Y-%m-%d")
    imported, alive, dead, skipped, errors = [], [], [], [], []
    for item in links:
        ip = item["ip"]
        if ip in existing_ips:
            skipped.append({"name": item["name"], "ip": ip, "reason": "server already in panel"})
            log(f"import: skip {item['name']} ({ip}) — server already present")
            continue
        name = item["name"]
        if name in existing_names:
            name = f"{name} ({today})"
        if dry_run:
            imported.append({"name": name, "ip": ip, "note": "dry-run, not imported"})
            continue
        try:
            created = mui.create_ext(name, item["link"])
        except MuiError as e:
            errors.append({"name": name, "ip": ip, "error": str(e)})
            log(f"import: create '{name}' failed: {e}")
            continue
        ext_id = created["id"]
        imported.append({"name": name, "ip": ip, "id": ext_id})
        existing_names.add(name)
        existing_ips.add(ip)
        log(f"import: created '{name}' (id {ext_id})")
        try:
            cells = mui.test_ext(ext_id)
        except MuiError as e:
            errors.append({"name": name, "ip": ip, "id": ext_id, "error": f"test error: {e}"})
            log(f"import: test '{name}' error: {e} (kept, needs manual check)")
            continue
        verdict, delay = test_cells_verdict(cells)
        if verdict == "alive":
            alive.append({"name": name, "ip": ip, "id": ext_id, "delayMs": delay})
            log(f"import: '{name}' ALIVE ({delay} ms)")
        elif verdict == "dead":
            current = {e["id"]: e.get("name") for e in mui.list_exts()}
            if current.get(ext_id) == name:
                mui.delete_ext(ext_id)
                dead.append({"name": name, "ip": ip, "id": ext_id})
                log(f"import: '{name}' dead, deleted")
            else:
                errors.append({"name": name, "ip": ip, "id": ext_id,
                               "error": "id/name mismatch on re-check, not deleted"})
        else:
            errors.append({"name": name, "ip": ip, "id": ext_id,
                           "error": "speed test inconclusive, kept for manual check"})
            log(f"import: '{name}' test inconclusive, kept")
    return {"imported": imported, "alive": alive, "dead": dead,
            "skipped": skipped, "errors": errors}


# ---------------------------------------------------------------- main
def run(args):
    started = time.time()
    status = {"date": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
              "status": "error", "stage": "start", "errors": [],
              "degraded": [], "counts": {}}
    detail = {}
    try:
        # 1-2. subscription + candidates
        text = download_subscription()
        proxies = parse_proxies(text)
        tested = set(load_json(TESTED_PATH, []))
        candidates = build_candidates(proxies, tested)
        status["counts"]["subscription_nodes"] = len(proxies)
        status["counts"]["candidates"] = len(candidates)
        if not candidates:
            raise RuntimeError("no candidates after filtering")
        # 3-4. ASN screen + shortlist
        status["stage"] = "asn"
        asn, isp_like = asn_screen([c["ip"] for c in candidates])
        shortlist = pick_shortlist(candidates, asn, isp_like)
        detail["shortlist"] = shortlist
        status["counts"]["shortlist"] = len(shortlist)
        # 5. egress
        status["stage"] = "egress"
        eg = egress_scores([s["ip"] for s in shortlist])
        detail["egress"] = eg
        egress_pass = [s for s in shortlist
                       if (eg[s["ip"]].get("score") or 0) >= EGRESS_MIN_SCORE]
        status["counts"]["egress_pass"] = len(egress_pass)
        log(f"egress pass: {len(egress_pass)}/{len(shortlist)}")
        # 6. IPPure (degrade to egress-only on total failure)
        status["stage"] = "ippure"
        ip_res, ip_ok = ippure_scores([s["ip"] for s in egress_pass])
        detail["ippure"] = ip_res
        if ip_ok:
            final = [s for s in egress_pass
                     if (ip_res.get(s["ip"], {}).get("coef") is not None
                         and ip_res[s["ip"]]["coef"] < IPPURE_MAX_COEF)]
        else:
            status["degraded"].append("ippure-down-egress-only")
            final = egress_pass
        # rank: egress desc, ippure asc
        final.sort(key=lambda s: (-(eg[s["ip"]].get("score") or 0),
                                  ip_res.get(s["ip"], {}).get("coef") or 999))
        status["counts"]["final"] = len(final)
        log(f"final passers: {len(final)}")
        # record tested IPs (shortlist IPs, even if they failed later stages)
        tested |= {s["ip"] for s in shortlist}
        save_json(TESTED_PATH, sorted(tested))
        # 7. links (node names normalized so they land in the 其他 tab)
        cand = {c["ip"]: c["node"] for c in candidates}
        links = []
        used_names = set()
        for s in final:
            try:
                node = dict(cand[s["ip"]])
                node["name"] = normalize_name(s, used_names)
                links.append({"name": node["name"], "ip": s["ip"],
                              "link": build_link(node)})
            except Exception as e:
                status["errors"].append(f"link build {s['ip']}: {e}")
        detail["links"] = [{"name": l["name"], "ip": l["ip"]} for l in links]
        # 8-9. m-ui (unless skipped)
        if args.skip_mui:
            status["degraded"].append("mui-skipped")
            status["status"] = "ok"
        else:
            status["stage"] = "mui-login"
            creds = load_credentials()
            user, password = creds.get("MUI_USER"), creds.get("MUI_PASS")
            if not user or not password:
                raise RuntimeError("credentials file missing MUI_USER/MUI_PASS")
            mui = MuiClient()
            try:
                mui.login(user, password, creds.get("MUI_TOTP_SEED"))
            except TotpRequired as e:
                status["stage"] = "mui-totp-required"
                raise RuntimeError(str(e))
            log("m-ui login ok")
            try:
                if not args.no_cleanup:
                    status["stage"] = "mui-cleanup"
                    detail["cleanup"] = cleanup_exts(mui, args.dry_run)
                    status["counts"]["cleanup_deleted"] = len(detail["cleanup"]["deleted"])
                status["stage"] = "mui-import"
                detail["import"] = import_and_test(mui, links, args.dry_run)
                status["counts"]["imported"] = len(detail["import"]["imported"])
                status["counts"]["alive"] = len(detail["import"]["alive"])
                status["counts"]["dead_deleted"] = len(detail["import"]["dead"])
                # flat strings for the Xiaotu notifier (bash-friendly, no array parsing)
                status["survivors_text"] = "；".join(
                    f"{a['name']} ({a['ip']}, {a.get('delayMs')}ms)"
                    for a in detail["import"]["alive"]) or "无"
                status["cleanup_text"] = "；".join(
                    d["name"] for d in detail.get("cleanup", {}).get("deleted", [])) or "无"
            finally:
                mui.logout()
            status["status"] = "ok"
    except Exception as e:
        log(f"FATAL at stage {status['stage']}: {e}")
        status["errors"].append(f"{status['stage']}: {e}")
    status["duration_sec"] = round(time.time() - started)
    status["errors_text"] = "；".join(status["errors"][:2]) or ""
    status["degraded_text"] = "；".join(status["degraded"]) or ""
    save_json(STATUS_PATH, status)
    save_json(LASTRUN_PATH, {"status": status, "detail": detail})
    log(f"run finished: status={status['status']} duration={status['duration_sec']}s "
        f"counts={status['counts']}")
    return 0 if status["status"] == "ok" else 1


def main():
    ap = argparse.ArgumentParser(description="weekly free-node sweep for m-ui")
    ap.add_argument("--dry-run", action="store_true", help="no m-ui mutations")
    ap.add_argument("--skip-mui", action="store_true", help="pipeline only, no panel calls")
    ap.add_argument("--no-cleanup", action="store_true", help="skip pre-import cleanup")
    args = ap.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
