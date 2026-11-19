#!/usr/bin/env python3
"""IPPure API client (stdlib only).

Reproduces the ippure.com front-end handshake, decoded from the site's JS
(security chunk + deobfuscated ipinfo chunk, 2026-11-19):

  1. Unsigned GET https://api.123169.xyz/api/info/<endpoint>/<arg>
     -> {"ok":false} + response headers x-k (64-hex key) and x-t (server ms ts)
  2. Signed retry on the SAME TCP/TLS connection, headers:
       x-k: <key>
       x-t: <t>-<hmac>
     where t = Date.now() - t_recv_ms + server_t (server-synced estimate),
     hmac = HMAC-SHA256 hex of "GET-<full URL>--<t>" keyed by the x-k string.
     -> {"ok":true, "my_ip": "...", "data": {...}}

CRITICAL: the x-k is bound to the client IP as seen by the server. From this
VM the egress IP rotates per connection, so the two requests MUST share one
persistent connection. On GCP (fixed egress IP) separate connections would
probably also work, but the persistent-connection approach works everywhere,
so this client always uses it.

Endpoints (all GET, same handshake):
  /api/info/ip-risk/<ip>        -> data.risk_score (0-100, lower = cleaner)
  /api/info/ip-basic/<ip>       -> data: asn{number,organization,network,is_residential,type,domain},
                                   geo{IP2Location,DB-IP,MaxMind}, traits{is_broadcast,is_warp}
  /api/info/asn/botclass/<asn>  -> data: {bot, human} percentages
  /api/info/ipleak/<ip>         -> (not validated; same handshake expected)

Validated 2026-11-19 22:14-22:15 CST: all 11 round-4 IPs matched the browser
measurements EXACTLY (risk_score), and botclass human% matched too
(163.245.42.5 -> 21.61%).

Origin note: api.123169.xyz is the default origin. api.ippure.com is used
ONLY for IPv6-only visitors (the JS switches origin when the visitor has no
IPv4). GCP has IPv4, so always use api.123169.xyz.

Proxy: if https_proxy is set in the environment (this VM), the client opens
a CONNECT tunnel through it (auth taken from the env URL at runtime, never
stored). Otherwise it connects directly (GCP case).

Usage:
  python3 ippure.py 163.245.42.5            # full report, JSON
  python3 ippure.py --risk 1.2.3.4 5.6.7.8  # risk_score only, one per line
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse

HOST = "api.123169.xyz"
BASE_URL = f"https://{HOST}"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Referer": "https://ippure.com/",
    "Origin": "https://ippure.com",
}

MAX_RETRIES = 3  # browser retries while a response carries x-k, up to loopIndex 3


def _open_connection(host=HOST, timeout=30):
    """One persistent HTTPS connection; CONNECT tunnel if https_proxy is set."""
    proxy_url = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if proxy_url:
        p = urllib.parse.urlparse(proxy_url)
        auth = ""
        if p.username:
            auth = base64.b64encode(
                f"{p.username}:{p.password or ''}".encode()
            ).decode()
        sock = socket.create_connection((p.hostname, p.port), timeout=timeout)
        req = (f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n"
               + (f"Proxy-Authorization: Basic {auth}\r\n" if auth else "")
               + "\r\n")
        sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("proxy closed CONNECT")
            buf += chunk
        if b" 200" not in buf.split(b"\r\n")[0]:
            raise RuntimeError(f"CONNECT failed: {buf[:120]!r}")
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout)
        conn.sock = tls
        return conn
    return http.client.HTTPSConnection(host, 443, timeout=timeout)


class IPPureClient:
    """One persistent connection; handles the x-k/x-t handshake per call."""

    def __init__(self, host=HOST, timeout=30):
        self.host = host
        self.timeout = timeout
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None:
            self.conn = _open_connection(self.host, self.timeout)

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def _raw_get(self, path, headers):
        self._ensure_conn()
        self.conn.request("GET", path, headers=headers)
        resp = self.conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, resp.getheader("x-k"), resp.getheader("x-t"), body

    def get(self, path):
        """Signed GET. Returns parsed JSON dict (raises on repeated failure)."""
        last_body = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                status, xk, xt, body = self._raw_get(path, HEADERS)
            except (http.client.HTTPException, OSError):
                # Connection dropped mid-batch: reopen once and retry.
                self.close()
                if attempt == MAX_RETRIES:
                    raise
                continue
            last_body = body
            try:
                data = json.loads(body)
            except ValueError:
                data = {}
            if data.get("ok") is True:
                return data
            if not xk or not xt:
                # No challenge issued and not ok: nothing to sign with.
                break
            # Sign and retry on the same connection.
            t_recv = int(time.time() * 1000)
            t = int(time.time() * 1000) - t_recv + int(xt)
            msg = f"GET-{BASE_URL}{path}--{t}"
            sig = hmac.new(xk.encode(), msg.encode(),
                           hashlib.sha256).hexdigest()
            hd = dict(HEADERS)
            hd["x-k"] = xk
            hd["x-t"] = f"{t}-{sig}"
            try:
                status, xk2, xt2, body = self._raw_get(path, hd)
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt == MAX_RETRIES:
                    raise
                continue
            last_body = body
            try:
                data = json.loads(body)
            except ValueError:
                data = {}
            if data.get("ok") is True:
                return data
            # Server issued a fresh key: loop and re-sign with it.
            xk, xt = xk2, xt2
            if not xk or not xt:
                break
        raise RuntimeError(f"IPPure handshake failed for {path}: {last_body!r}")

    def risk(self, ip):
        """IPPure coefficient (0-100 int; lower = cleaner)."""
        return self.get(f"/api/info/ip-risk/{ip}")["data"]["risk_score"]

    def basic(self, ip):
        """ASN/geo/traits dict for an IP."""
        return self.get(f"/api/info/ip-basic/{ip}")["data"]

    def botclass(self, asn):
        """{"bot": float, "human": float} for an ASN number."""
        return self.get(f"/api/info/asn/botclass/{asn}")["data"]

    def full(self, ip):
        """Everything the browser report shows for one IP."""
        b = self.basic(ip)
        asn = b.get("asn", {}).get("number")
        out = {
            "ip": ip,
            "risk_score": self.risk(ip),
            "asn": b.get("asn"),
            "geo": b.get("geo"),
            "traits": b.get("traits"),
        }
        if asn:
            try:
                out["botclass"] = self.botclass(asn)
            except Exception as e:  # bot share is nice-to-have
                out["botclass"] = {"error": str(e)}
        return out


def main(argv):
    risk_only = "--risk" in argv
    ips = [a for a in argv[1:] if not a.startswith("--")]
    if not ips:
        print("usage: ippure.py [--risk] <ip> [<ip> ...]", file=sys.stderr)
        return 2
    client = IPPureClient()
    try:
        for ip in ips:
            if risk_only:
                print(f"{ip}\t{client.risk(ip)}")
            else:
                print(json.dumps(client.full(ip), ensure_ascii=False))
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
