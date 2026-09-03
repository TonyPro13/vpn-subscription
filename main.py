from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import tempfile
import time
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS_WEAK_DPI_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
]

SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
STATE_FILE = Path("data/state.json")
OUT_DIR = Path("output")
BIN_DIR = Path("bin")
XRAY = BIN_DIR / "xray"
SINGBOX = BIN_DIR / "sing-box"
GEOIP_COUNTRY_DB = Path("data/GeoLite2-Country.mmdb")

CHEAP_PROBE_SEMAPHORE = None
VPN_PROCESS_SEMAPHORE = None

CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "20"))
VPN_PROCESS_CONCURRENCY = int(os.getenv("VPN_PROCESS_CONCURRENCY", "40"))
PROBE_TIMEOUT = float(os.getenv("PROBE_TIMEOUT_SECONDS", "9"))

CHATGPT_PROBE_URL = os.getenv(
    "CHATGPT_PROBE_URL",
    "https://chatgpt.com/robots.txt",
)

CHATGPT_AUTH_PROBE_URL = os.getenv(
    "CHATGPT_AUTH_PROBE_URL",
    "https://auth.openai.com/",
)

CHATGPT_ANDROID_PROBE_URL = os.getenv(
    "CHATGPT_ANDROID_PROBE_URL",
    "https://android.chat.openai.com/",
)

YOUTUBE_PROBE_URL = os.getenv(
    "YOUTUBE_PROBE_URL",
    "https://www.youtube.com/generate_204",
)

YOUTUBE_PROBE_TIMEOUT = float(
    os.getenv("YOUTUBE_PROBE_TIMEOUT_SECONDS", "5")
)

TELEGRAM_HTTPS_PROBE_URL = os.getenv(
    "TELEGRAM_HTTPS_PROBE_URL",
    "https://venus.web.telegram.org/api",
)

TELEGRAM_PROBE_TIMEOUT = float(
    os.getenv("TELEGRAM_PROBE_TIMEOUT_SECONDS", "3")
)

TELEGRAM_MTPROTO_ENDPOINTS = (
    ("149.154.167.50", 443),
    ("149.154.167.51", 443),
)

WHATSAPP_PROBE_TIMEOUT = float(
    os.getenv("WHATSAPP_PROBE_TIMEOUT_SECONDS", "2")
)

WHATSAPP_PROBE_ENDPOINTS = (
    "e1.whatsapp.net",
    "e2.whatsapp.net",
    "e3.whatsapp.net",
)

WHATSAPP_PROBE_PORTS = (443, 5222)

INSTAGRAM_PROBE_URL = os.getenv(
    "INSTAGRAM_PROBE_URL",
    "https://www.instagram.com/",
)

# One Cloudflare target is used everywhere Mihomo measures node latency:
# - preliminary dead-node filter before the service cascade;
# - final delay measurement used for publication ordering;
# - client-side provider/AUTO health checks.
MIHOMO_AUTO_TEST_URL = "https://cp.cloudflare.com"

MIHOMO_PING_TEST_URL = os.getenv(
    "MIHOMO_PING_TEST_URL",
    MIHOMO_AUTO_TEST_URL,
)

MIHOMO_PING_TIMEOUT_MS = int(
    os.getenv("MIHOMO_PING_TIMEOUT_MS", "5000")
)

MIHOMO_START_TIMEOUT = float(
    os.getenv("MIHOMO_START_TIMEOUT_SECONDS", "5")
)

QUALITY_MAX_SECONDS = float(os.getenv("QUALITY_MAX_SECONDS", "5"))
MAX_PUBLISHED_NODES = None

async def curl_tls_probe(port: int, name: str, url: str):
    proc = await asyncio.create_subprocess_exec(
        "curl",
        "-sS",
        "--max-time",
        str(max(1, int(PROBE_TIMEOUT))),
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "-o",
        os.devnull,
        "-w",
        "%{http_code} %{time_total}",
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        out, err = await asyncio.wait_for(
            proc.communicate(),
            timeout=PROBE_TIMEOUT + 2,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return Probe(False, error=f"{name}: timeout")

    text = out.decode(errors="replace").strip()
    parts = text.split()

    code = parts[0] if parts else ""

    try:
        total_seconds = float(parts[1])
    except (IndexError, ValueError):
        total_seconds = PROBE_TIMEOUT + 1

    if proc.returncode != 0:
        error_text = err.decode(errors="replace").strip()
        return Probe(
            False,
            error=f"{name}: TLS/HTTPS failed: {error_text[-300:]}",
        )

    if not code or code == "000":
        return Probe(
            False,
            error=f"{name}: no HTTP response",
        )

    return Probe(
        True,
        latency_ms=round(total_seconds * 1000, 1),
    )

QUALITY_PROBES = (
    ("chatgpt", CHATGPT_PROBE_URL, {"200"}),
)


@dataclass
class Probe:
    ok: bool
    latency_ms: float | None = None
    error: str | None = None


def q1(q, key, default=""):
    v = q.get(key)
    return v[0] if v else default


def b64decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())




def uri_userinfo(uri: str) -> str:
    """Return the complete decoded URI userinfo before @."""
    try:
        p = urlsplit(uri)
        if "@" not in p.netloc:
            return ""
        return unquote(p.netloc.rsplit("@", 1)[0])
    except Exception:
        return ""


def qbool(q, *keys) -> bool:
    truthy = {"1", "true", "yes", "on"}
    for key in keys:
        value = q1(q, key, "")
        if str(value).strip().lower() in truthy:
            return True
    return False


def split_csv(value: str):
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def parse_vmess_uri(uri: str) -> dict:
    raw = uri[len("vmess://"):].split("#", 1)[0]
    return json.loads(b64decode(raw).decode("utf-8", errors="strict"))


def parse_ss_uri(uri: str):
    """Parse SIP002 Shadowsocks URI and return method, password, host, port."""
    raw = uri[len("ss://"):].split("#", 1)[0].split("?", 1)[0]

    if "@" in raw:
        cred_raw, addr = raw.rsplit("@", 1)
        cred_decoded = unquote(cred_raw)
        if ":" not in cred_decoded:
            cred_decoded = b64decode(cred_raw).decode("utf-8", errors="strict")
    else:
        decoded = b64decode(raw).decode("utf-8", errors="strict")
        cred_decoded, addr = decoded.rsplit("@", 1)

    method, password = cred_decoded.split(":", 1)
    ap = urlsplit("ss://x@" + addr)
    if not ap.hostname or ap.port is None:
        raise ValueError("invalid Shadowsocks server address")
    return method, password, ap.hostname, ap.port



def canonical(uri: str) -> str:
    """
    Conservative semantic key used only for deduplication.

    It removes display-only fragments and normalizes query order. For VLESS,
    only protocol defaults that are explicitly defined by the share-link
    specification and already match our Xray/Mihomo behavior are normalized:
    omitted encryption/security are treated as "none".

    Endpoint, credentials, transports, TLS/REALITY fields, fingerprints and
    unknown parameters remain significant. If a URI repeats the same query
    field, semantic normalization is intentionally skipped because such input
    is ambiguous/non-standard and must not be collapsed aggressively.
    """
    uri = uri.strip()

    def raw_key():
        return "raw-uri:" + uri.split("#", 1)[0].strip()

    def normalized_query_pairs(query: str, *, vless_defaults: bool = False):
        pairs = parse_qsl(query, keep_blank_values=True)
        names = [key for key, _ in pairs]

        # Repeated URL fields are non-standard/ambiguous. Preserve their raw
        # order instead of sorting them into a potentially false duplicate.
        if len(names) != len(set(names)):
            return None

        if vless_defaults:
            present = set(names)
            if "encryption" not in present:
                pairs.append(("encryption", "none"))
            if "security" not in present:
                pairs.append(("security", "none"))

        return sorted(pairs)

    try:
        scheme = uri.split("://", 1)[0].lower()
        canonical_scheme = "hysteria2" if scheme == "hy2" else scheme

        if scheme == "vmess":
            data = dict(parse_vmess_uri(uri))
            for cosmetic_key in ("ps", "remark", "remarks", "name"):
                data.pop(cosmetic_key, None)
            if data.get("add"):
                data["add"] = str(data["add"]).lower().rstrip(".")
            if data.get("port") is not None:
                data["port"] = str(data["port"])
            return "vmess:" + json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

        if scheme == "ss":
            method, password, host, port = parse_ss_uri(uri)
            p = urlsplit(uri)
            query_pairs = normalized_query_pairs(p.query)
            if query_pairs is None:
                return raw_key()
            payload = {
                "scheme": "ss",
                "method": method,
                "password": password,
                "host": host.lower().rstrip("."),
                "port": port,
                "query": query_pairs,
            }
            return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        p = urlsplit(uri)
        query_pairs = normalized_query_pairs(
            p.query,
            vless_defaults=(scheme == "vless"),
        )
        if query_pairs is None:
            return raw_key()

        host = (p.hostname or "").lower().rstrip(".")
        payload = {
            "scheme": canonical_scheme,
            "userinfo": uri_userinfo(uri),
            "host": host,
            "port": p.port,
            "path": p.path,
            "query": query_pairs,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        # Fall back to the raw URI without its display fragment.
        return raw_key()




def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "VPN-Subscription-Builder/0.3"})
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")



def extract_server_host(uri: str):
    try:
        scheme = uri.split("://", 1)[0].lower()

        if scheme == "vmess":
            host = parse_vmess_uri(uri).get("add")
            return str(host).strip() if host else None

        if scheme == "ss":
            _, _, host, _ = parse_ss_uri(uri)
            return host

        return urlsplit(uri).hostname

    except Exception:
        return None



def _resolve_host_ips(host: str):
    if not host:
        return []

    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []

    result = []
    seen = set()
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        key = str(ip)
        if key not in seen:
            seen.add(key)
            result.append(ip)
    return result


def _country_flag(iso_code: str) -> str:
    code = (iso_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(127397 + ord(ch)) for ch in code)


def geo_country_label(host: str):
    """
    Optional GeoIP enrichment for fallback names only.
    Source-provided names/fragments always take priority.
    """
    if not host or not GEOIP_COUNTRY_DB.exists():
        return None

    try:
        import geoip2.database
    except Exception:
        return None

    ips = _resolve_host_ips(host)
    if not ips:
        return None

    try:
        with geoip2.database.Reader(str(GEOIP_COUNTRY_DB)) as reader:
            for ip in ips:
                try:
                    country = reader.country(str(ip)).country
                except Exception:
                    continue
                code = country.iso_code or ""
                name = (country.names or {}).get("en") or code
                if name:
                    flag = _country_flag(code)
                    return f"{flag} {name}".strip()
    except Exception:
        return None

    return None



def detect_country_label_from_host(host: str):
    return geo_country_label(host)




def collect_sources():
    """
    Collect supported VPN candidates without changing the original URI.

    The raw source URI is preserved for tunnel testing and subscription output.
    Deduplication uses canonical() only, so display-name differences and query
    ordering are ignored but real connection parameters remain distinct.
    """
    unique = {}
    source_stats = {}
    source_parse_stats = {}
    duplicates = 0

    for url in SOURCES:
        source_stats[url] = 0
        source_parse_stats[url] = {
            "parsed": 0,
            "malformed": 0,
            "duplicates_after_global_dedup": 0,
            "unique_contribution": 0,
        }

        try:
            source_text = fetch(url)
        except Exception as e:
            print(f"WARNING: failed to load source {url}: {e}")
            continue

        if "://" not in source_text:
            try:
                decoded = b64decode(source_text).decode("utf-8", errors="replace")
                if "://" in decoded:
                    source_text = decoded
            except Exception:
                pass

        for line in source_text.splitlines():
            uri = line.strip()
            if not uri or uri.startswith("#") or "://" not in uri:
                continue

            scheme = uri.split("://", 1)[0].lower()
            if scheme not in SUPPORTED:
                continue

            host = extract_server_host(uri)
            if not host:
                source_parse_stats[url]["malformed"] += 1
                continue

            # "parsed" is intentionally counted before global dedup so we can
            # see how many valid configs each source actually supplied.
            source_parse_stats[url]["parsed"] += 1

            key = canonical(uri)
            if key in unique:
                duplicates += 1
                source_parse_stats[url]["duplicates_after_global_dedup"] += 1
                continue

            source_stats[url] += 1
            source_parse_stats[url]["unique_contribution"] += 1
            unique[key] = uri

    print(json.dumps({"source_parse_stats": source_parse_stats}, ensure_ascii=False, indent=2))
    return unique, source_stats, duplicates


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data.get("nodes", {})
    except Exception:
        return {}



def stream_settings(q):
    security = (q1(q, "security", "none") or "none").strip().lower()
    if security in {"false", "0", "off", "no"}:
        security = "none"

    network = (q1(q, "type", "tcp") or "tcp").strip().lower()
    if network == "raw":
        network = "tcp"

    st = {"network": network, "security": security}

    if security == "tls":
        tls = {"serverName": q1(q, "sni", "")}
        fp = q1(q, "fp", "")
        if fp:
            tls["fingerprint"] = fp
        alpn = split_csv(q1(q, "alpn", ""))
        if alpn:
            tls["alpn"] = alpn
        if qbool(q, "allowInsecure", "insecure"):
            tls["allowInsecure"] = True
        st["tlsSettings"] = tls

    elif security == "reality":
        st["realitySettings"] = {
            "serverName": q1(q, "sni", ""),
            "fingerprint": q1(q, "fp", "chrome"),
            "publicKey": q1(q, "pbk", ""),
            "shortId": q1(q, "sid", ""),
            "spiderX": q1(q, "spx", ""),
        }

    if network == "ws":
        ws = {"path": unquote(q1(q, "path", "/"))}
        host = q1(q, "host", "")
        if host:
            ws["headers"] = {"Host": host}
        st["wsSettings"] = ws

    elif network == "grpc":
        st["grpcSettings"] = {
            "serviceName": q1(q, "serviceName", q1(q, "service_name", ""))
        }

    elif network == "httpupgrade":
        st["httpupgradeSettings"] = {
            "path": unquote(q1(q, "path", "/")),
            "host": q1(q, "host", ""),
        }

    elif network == "xhttp":
        xhttp = {
            "path": unquote(q1(q, "path", "/")),
            "host": q1(q, "host", ""),
            "mode": q1(q, "mode", "auto"),
        }

        extra_raw = q1(q, "extra", "")
        if extra_raw:
            try:
                extra = json.loads(extra_raw)
                if isinstance(extra, dict):
                    xhttp["extra"] = extra
            except Exception:
                pass
        elif q1(q, "x_padding_bytes", ""):
            xhttp["xPaddingBytes"] = q1(q, "x_padding_bytes", "")

        st["xhttpSettings"] = xhttp

    return st



def xray_outbound(uri: str):
    p = urlsplit(uri)
    q = parse_qs(p.query, keep_blank_values=True)
    scheme = p.scheme.lower()

    if scheme == "vless":
        return {
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": p.hostname,
                "port": p.port,
                "users": [{
                    "id": unquote(p.username or ""),
                    "encryption": q1(q, "encryption", "none"),
                    "flow": q1(q, "flow", ""),
                }]
            }]},
            "streamSettings": stream_settings(q),
        }

    if scheme == "trojan":
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": p.hostname,
                "port": p.port,
                "password": uri_userinfo(uri),
            }]},
            "streamSettings": stream_settings(q),
        }

    if scheme == "vmess":
        o = parse_vmess_uri(uri)
        fake_q = {
            "type": [o.get("net", "tcp")],
            "security": [o.get("tls", "") or "none"],
            "sni": [o.get("sni", "")],
            "host": [o.get("host", "")],
            "path": [o.get("path", "")],
            "fp": [o.get("fp", "")],
            "alpn": [o.get("alpn", "")],
            "serviceName": [o.get("serviceName", o.get("service_name", ""))],
            "mode": [o.get("mode", "auto")],
            "allowInsecure": [str(
                o.get(
                    "allowInsecure",
                    o.get("insecure", o.get("skip-cert-verify", "0")),
                )
            )],
        }
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": o["add"],
                "port": int(o["port"]),
                "users": [{
                    "id": o["id"],
                    "alterId": int(o.get("aid", 0) or 0),
                    "security": o.get("scy", "auto"),
                }]
            }]},
            "streamSettings": stream_settings(fake_q),
        }

    if scheme == "ss":
        method, password, host, port = parse_ss_uri(uri)
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]}
        }

    raise ValueError(f"unsupported by xray adapter: {scheme}")


def xray_config(uri: str, port: int):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": True},
            "tag": "probe-in",
        }],
        "outbounds": [
            dict(xray_outbound(uri), tag="probe-out"),
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["probe-in"],
                "outboundTag": "probe-out",
            }]
        },
    }



def singbox_config(uri: str, port: int):
    p = urlsplit(uri)
    q = parse_qs(p.query, keep_blank_values=True)
    scheme = p.scheme.lower()
    if scheme not in {"hysteria2", "hy2"}:
        raise ValueError("sing-box adapter currently handles Hysteria2/Hy2 only")

    tls = {
        "enabled": True,
        "server_name": q1(q, "sni", p.hostname or ""),
        "insecure": qbool(q, "insecure", "allowInsecure"),
    }
    alpn = split_csv(q1(q, "alpn", ""))
    if alpn:
        tls["alpn"] = alpn

    fp = q1(q, "fp", "")
    if fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    outbound = {
        "type": "hysteria2",
        "tag": "probe-out",
        "server": p.hostname,
        "server_port": p.port,
        "password": uri_userinfo(uri),
        "tls": tls,
    }

    up = q1(q, "upmbps", "")
    down = q1(q, "downmbps", "")
    try:
        if up:
            outbound["up_mbps"] = int(float(up))
        if down:
            outbound["down_mbps"] = int(float(down))
    except ValueError:
        pass

    obfs = q1(q, "obfs", "")
    if obfs:
        outbound["obfs"] = {
            "type": obfs,
            "password": q1(q, "obfs-password", q1(q, "obfs_password", "")),
        }

    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "socks",
            "tag": "probe-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [outbound],
        "route": {"final": "probe-out"},
    }


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def wait_port(port: int, timeout=2.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.05)
    return False

async def youtube_generate_204_probe(port: int):
    proc = await asyncio.create_subprocess_exec(
        "curl",
        "-sS",
        "--max-time",
        str(max(1, int(YOUTUBE_PROBE_TIMEOUT))),
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "-o",
        os.devnull,
        "-w",
        "%{http_code} %{time_total}",
        YOUTUBE_PROBE_URL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        out, err = await asyncio.wait_for(
            proc.communicate(),
            timeout=YOUTUBE_PROBE_TIMEOUT + 2,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()

        return Probe(
            False,
            error="youtube_204: timeout",
        )

    text = out.decode(errors="replace").strip()
    parts = text.split()

    code = parts[0] if parts else ""

    try:
        total_seconds = float(parts[1])
    except (IndexError, ValueError):
        total_seconds = YOUTUBE_PROBE_TIMEOUT + 1

    if proc.returncode != 0:
        error_text = err.decode(errors="replace").strip()

        return Probe(
            False,
            error=(
                "youtube_204: connection failed: "
                f"{error_text[-300:]}"
            ),
        )

    if code != "204":
        return Probe(
            False,
            latency_ms=round(total_seconds * 1000, 1),
            error=(
                f"youtube_204: unexpected HTTP status {code}"
            ),
        )

    return Probe(
        True,
        latency_ms=round(total_seconds * 1000, 1),
    )


async def telegram_https_probe(port: int):
    proc = await asyncio.create_subprocess_exec(
        "curl",
        "-sS",
        "--max-time",
        str(max(1, int(TELEGRAM_PROBE_TIMEOUT))),
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "-o",
        os.devnull,
        "-w",
        "%{http_code} %{time_total}",
        TELEGRAM_HTTPS_PROBE_URL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        out, err = await asyncio.wait_for(
            proc.communicate(),
            timeout=TELEGRAM_PROBE_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return Probe(False, error="telegram_https: timeout")

    text = out.decode(errors="replace").strip()
    parts = text.split()
    code = parts[0] if parts else ""

    try:
        total_seconds = float(parts[1])
    except (IndexError, ValueError):
        total_seconds = TELEGRAM_PROBE_TIMEOUT + 1

    if proc.returncode != 0:
        error_text = err.decode(errors="replace").strip()
        return Probe(
            False,
            error=f"telegram_https: TLS/HTTPS failed: {error_text[-300:]}",
        )

    if not code or code == "000":
        return Probe(False, error="telegram_https: no HTTP response")

    return Probe(
        True,
        latency_ms=round(total_seconds * 1000, 1),
    )


async def _socks5_connect_ipv4(local_port: int, host: str, remote_port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)

    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        reply = await reader.readexactly(2)
        if reply != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 auth negotiation failed: {reply.hex()}")

        request = (
            b"\x05\x01\x00\x01"
            + socket.inet_aton(host)
            + struct.pack(">H", remote_port)
        )
        writer.write(request)
        await writer.drain()

        head = await reader.readexactly(4)
        if head[0] != 5 or head[1] != 0:
            raise RuntimeError(
                f"SOCKS5 connect failed: version={head[0]} code={head[1]}"
            )

        atyp = head[3]
        if atyp == 1:
            await reader.readexactly(4)
        elif atyp == 3:
            size = (await reader.readexactly(1))[0]
            await reader.readexactly(size)
        elif atyp == 4:
            await reader.readexactly(16)
        else:
            raise RuntimeError(f"SOCKS5 returned unknown ATYP={atyp}")

        await reader.readexactly(2)
        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def _socks5_connect_domain(local_port: int, host: str, remote_port: int):
    """Open SOCKS5 CONNECT using a domain name so resolution happens via VPN."""
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)

    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        reply = await reader.readexactly(2)
        if reply != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 auth negotiation failed: {reply.hex()}")

        host_bytes = host.encode("idna")
        if not 1 <= len(host_bytes) <= 255:
            raise RuntimeError("SOCKS5 domain name length is invalid")

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack(">H", remote_port)
        )
        writer.write(request)
        await writer.drain()

        head = await reader.readexactly(4)
        if head[0] != 5 or head[1] != 0:
            raise RuntimeError(
                f"SOCKS5 connect failed: version={head[0]} code={head[1]}"
            )

        atyp = head[3]
        if atyp == 1:
            await reader.readexactly(4)
        elif atyp == 3:
            size = (await reader.readexactly(1))[0]
            await reader.readexactly(size)
        elif atyp == 4:
            await reader.readexactly(16)
        else:
            raise RuntimeError(f"SOCKS5 returned unknown ATYP={atyp}")

        await reader.readexactly(2)
        return reader, writer

    except BaseException:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def _whatsapp_port_probe(local_port: int, host: str, remote_port: int):
    """One WhatsApp TCP-connect attempt through the node SOCKS tunnel."""
    started = time.monotonic()
    writer = None

    try:
        _, writer = await asyncio.wait_for(
            _socks5_connect_domain(local_port, host, remote_port),
            timeout=WHATSAPP_PROBE_TIMEOUT,
        )
        return Probe(
            True,
            latency_ms=round((time.monotonic() - started) * 1000, 1),
        )
    except asyncio.TimeoutError:
        return Probe(False, error=f"{host}:{remote_port}: timeout")
    except Exception as e:
        return Probe(
            False,
            error=f"{host}:{remote_port}: {type(e).__name__}: {e}",
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _whatsapp_endpoint_probe(local_port: int, host: str):
    """
    Test ports 443 and 5222 for one WhatsApp endpoint in parallel.
    The endpoint passes as soon as either port connects successfully.
    """
    tasks = [
        asyncio.create_task(_whatsapp_port_probe(local_port, host, remote_port))
        for remote_port in WHATSAPP_PROBE_PORTS
    ]
    pending = set(tasks)
    errors = []

    try:
        while pending:
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in done:
                result = await task
                if result.ok:
                    for other in pending:
                        other.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    return result
                errors.append(result.error or f"{host}: failed")

        return Probe(
            False,
            error=f"{host}: both ports failed: " + " | ".join(errors),
        )
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def whatsapp_core_probe(local_port: int):
    """
    Adaptive WhatsApp core check:
    - e1 and e2 are checked in parallel;
    - each endpoint checks 443 and 5222 in parallel;
    - 2 of 3 endpoints must pass;
    - e3 is checked only when exactly one of e1/e2 passes.
    """
    first_results = await asyncio.gather(
        *(
            _whatsapp_endpoint_probe(local_port, host)
            for host in WHATSAPP_PROBE_ENDPOINTS[:2]
        )
    )

    passed = sum(1 for result in first_results if result.ok)

    if passed == 2:
        # Availability gate only: do not change the existing publication latency
        # ranking with this TCP-connect measurement.
        return Probe(True)

    if passed == 0:
        errors = [result.error for result in first_results if result.error]
        return Probe(
            False,
            error="whatsapp_core: e1/e2 both failed: " + " | ".join(errors),
        )

    third_host = WHATSAPP_PROBE_ENDPOINTS[2]
    third_result = await _whatsapp_endpoint_probe(local_port, third_host)

    if third_result.ok:
        return Probe(True)

    first_failed = next(
        (result.error for result in first_results if not result.ok),
        "one of e1/e2 failed",
    )
    return Probe(
        False,
        error=(
            "whatsapp_core: only 1 of 3 endpoints passed: "
            f"{first_failed} | {third_result.error or third_host + ': failed'}"
        ),
    )


def _mtproto_message_id() -> int:
    return int(time.time() * (1 << 32)) & ~3


async def _telegram_req_pq_once(local_port: int, host: str, remote_port: int):
    started = time.monotonic()
    reader = writer = None

    try:
        reader, writer = await asyncio.wait_for(
            _socks5_connect_ipv4(local_port, host, remote_port),
            timeout=TELEGRAM_PROBE_TIMEOUT,
        )

        nonce = secrets.token_bytes(16)
        body = struct.pack("<I", 0xBE7E8EF1) + nonce
        payload = (
            b"\x00" * 8
            + struct.pack("<Q", _mtproto_message_id())
            + struct.pack("<I", len(body))
            + body
        )

        if len(payload) % 4:
            raise RuntimeError("MTProto payload length is not divisible by 4")

        words = len(payload) // 4
        if not 1 <= words <= 0x7E:
            raise RuntimeError("unexpected abridged MTProto packet size")

        writer.write(b"\xef" + bytes([words]) + payload)
        await writer.drain()

        first = await asyncio.wait_for(
            reader.readexactly(1),
            timeout=TELEGRAM_PROBE_TIMEOUT,
        )
        first_len = first[0]

        if first_len == 0x7F:
            more = await reader.readexactly(3)
            response_words = int.from_bytes(more, "little")
        elif 1 <= first_len <= 0x7E:
            response_words = first_len
        else:
            raise RuntimeError(
                f"invalid abridged MTProto response length byte: 0x{first_len:02x}"
            )

        response_len = response_words * 4
        if response_len < 40 or response_len > 4096:
            raise RuntimeError(f"unexpected MTProto response size: {response_len}")

        response = await asyncio.wait_for(
            reader.readexactly(response_len),
            timeout=TELEGRAM_PROBE_TIMEOUT,
        )

        if response[:8] != b"\x00" * 8:
            raise RuntimeError("unexpected encrypted MTProto response")

        body_len = struct.unpack_from("<I", response, 16)[0]
        if body_len < 36 or 20 + body_len > len(response):
            raise RuntimeError(f"invalid MTProto body length: {body_len}")

        constructor = struct.unpack_from("<I", response, 20)[0]
        if constructor != 0x05162463:
            raise RuntimeError(
                f"unexpected MTProto constructor: 0x{constructor:08x}"
            )

        returned_nonce = response[24:40]
        if returned_nonce != nonce:
            raise RuntimeError("MTProto resPQ nonce mismatch")

        return Probe(
            True,
            latency_ms=round((time.monotonic() - started) * 1000, 1),
        )

    except asyncio.TimeoutError:
        return Probe(False, error=f"telegram_mtproto: {host}: timeout")
    except Exception as e:
        return Probe(
            False,
            error=f"telegram_mtproto: {host}: {type(e).__name__}: {e}",
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def telegram_mtproto_probe(port: int):
    errors = []

    for host, remote_port in TELEGRAM_MTPROTO_ENDPOINTS:
        result = await _telegram_req_pq_once(port, host, remote_port)
        if result.ok:
            return result
        errors.append(result.error or f"{host}: failed")

    return Probe(
        False,
        error="telegram_mtproto: all DC probes failed: " + " | ".join(errors),
    )


async def curl_url_probe(port: int, name: str, url: str, ok_codes, quality_max_seconds: float | None = None):
    proc = await asyncio.create_subprocess_exec(
        "curl", "-sS",
        "--max-time", str(max(1, int(PROBE_TIMEOUT))),
        "--proxy", f"socks5h://127.0.0.1:{port}",
        "-o", os.devnull,
        "-w", "%{http_code} %{time_total}",
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        out, err = await asyncio.wait_for(
            proc.communicate(),
            timeout=PROBE_TIMEOUT + 2,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return Probe(False, error=f"{name}: timeout")

    text = out.decode(errors="replace").strip()
    parts = text.split()

    code = parts[0] if parts else ""

    try:
        total_seconds = float(parts[1])
    except (IndexError, ValueError):
        total_seconds = PROBE_TIMEOUT + 1

    if proc.returncode != 0:
        error_text = err.decode(errors="replace")[-300:]
        return Probe(
            False,
            error=f"{name}: {error_text or 'HTTPS/TLS request failed'}",
        )

    if code not in ok_codes:
        return Probe(
            False,
            error=f"{name}: unexpected HTTP status {code}",
        )

    if quality_max_seconds is not None and total_seconds > quality_max_seconds:
        return Probe(
            False,
            error=f"{name}: too slow ({total_seconds:.2f}s)",
        )

    return Probe(
        True,
        latency_ms=round(total_seconds * 1000, 1),
    )


async def instagram_https_probe(port: int):
    """Mandatory Instagram availability gate through the node SOCKS tunnel.

    A real HTTPS response from www.instagram.com is enough to prove reachability.
    The exact HTTP status is intentionally not restricted because Instagram may
    legitimately return redirects or access-control responses to unauthenticated
    clients. This probe is availability-only and does not affect publication ranking.
    """
    result = await curl_tls_probe(port, "instagram_https", INSTAGRAM_PROBE_URL)
    if not result.ok:
        return result
    return Probe(True)


async def quality_probe(
    port: int,
    probe_stats: dict,
):
    """Full mandatory cascade:
    ChatGPT (3 checks), YouTube, Telegram HTTPS, Telegram MTProto, WhatsApp core,
    Instagram HTTPS. Any failure rejects the node immediately.
    """
    latencies = []

    async def count_probe(name, result):
        if not result.ok:
            probe_stats[name]["failed"] += 1
            return result
        probe_stats[name]["passed"] += 1
        if result.latency_ms is not None:
            latencies.append(result.latency_ms)
        return None

    # ChatGPT main check
    name, url, ok_codes = QUALITY_PROBES[0]
    probe_stats[name]["checked"] += 1
    async with CHEAP_PROBE_SEMAPHORE:
        result = await curl_url_probe(
            port,
            name,
            url,
            ok_codes,
            quality_max_seconds=QUALITY_MAX_SECONDS,
        )
    failed = await count_probe(name, result)
    if failed:
        return failed

    # Additional ChatGPT checks
    for extra_name, extra_url in (
        ("chatgpt_auth_tls", CHATGPT_AUTH_PROBE_URL),
        ("chatgpt_android_tls", CHATGPT_ANDROID_PROBE_URL),
    ):
        probe_stats[extra_name]["checked"] += 1
        async with CHEAP_PROBE_SEMAPHORE:
            result = await curl_tls_probe(port, extra_name, extra_url)
        failed = await count_probe(extra_name, result)
        if failed:
            return failed

    # YouTube check
    probe_stats["youtube_204"]["checked"] += 1
    async with CHEAP_PROBE_SEMAPHORE:
        result = await youtube_generate_204_probe(port)
    failed = await count_probe("youtube_204", result)
    if failed:
        return failed

    # Telegram HTTPS check
    probe_stats["telegram_https"]["checked"] += 1
    async with CHEAP_PROBE_SEMAPHORE:
        result = await telegram_https_probe(port)
    failed = await count_probe("telegram_https", result)
    if failed:
        return failed

    # Telegram MTProto check
    probe_stats["telegram_mtproto"]["checked"] += 1
    result = await telegram_mtproto_probe(port)
    failed = await count_probe("telegram_mtproto", result)
    if failed:
        return failed

    # WhatsApp core check: e1/e2 first, e3 only if needed; 2 of 3 required.
    probe_stats["whatsapp_core"]["checked"] += 1
    async with CHEAP_PROBE_SEMAPHORE:
        result = await whatsapp_core_probe(port)
    failed = await count_probe("whatsapp_core", result)
    if failed:
        return failed

    # Instagram availability check. This is a gate only and does not contribute
    # latency to the publication ranking.
    probe_stats["instagram_https"]["checked"] += 1
    async with CHEAP_PROBE_SEMAPHORE:
        result = await instagram_https_probe(port)
    failed = await count_probe("instagram_https", result)
    if failed:
        return failed

    return Probe(
        True,
        latency_ms=round(sum(latencies) / len(latencies), 1) if latencies else None,
    )



async def run_probe(uri: str, probe_stats: dict):
    """
    Creates a temporary VPN tunnel and runs the existing mandatory service
    cascade. Geography and preliminary DNS latency filters are not checked.
    """
    engine = None
    process = None
    port = free_port()
    cfg_file = None

    try:
        scheme = uri.split("://", 1)[0].lower()

        if scheme in {"hysteria2", "hy2"}:
            engine = str(SINGBOX)
            config = singbox_config(uri, port)
        else:
            engine = str(XRAY)
            config = xray_config(uri, port)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as f:
            json.dump(config, f, ensure_ascii=False)
            cfg_file = f.name

        process = await asyncio.create_subprocess_exec(
            engine,
            "run",
            "-c",
            cfg_file,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        if not await wait_port(port):
            return Probe(False, error=f"{scheme}: socks port not opened")

        return await quality_probe(port, probe_stats)

    except Exception as e:
        return Probe(False, error=f"{type(e).__name__}: {e}")

    finally:
        if process is not None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        if cfg_file:
            try:
                Path(cfg_file).unlink(missing_ok=True)
            except Exception:
                pass





def _xhttp_extra_to_mihomo(q):
    opts = {}
    extra_raw = q1(q, "extra", "")
    extra = {}
    if extra_raw:
        try:
            value = json.loads(extra_raw)
            if isinstance(value, dict):
                extra = value
        except Exception:
            extra = {}

    x_padding = (
        extra.get("xPaddingBytes")
        or q1(q, "x_padding_bytes", "")
        or q1(q, "xPaddingBytes", "")
    )
    if x_padding:
        opts["x-padding-bytes"] = str(x_padding)

    mapping = {
        "noGRPCHeader": "no-grpc-header",
        "xPaddingObfsMode": "x-padding-obfs-mode",
        "xPaddingKey": "x-padding-key",
    }
    for source_key, target_key in mapping.items():
        if source_key in extra:
            opts[target_key] = extra[source_key]

    headers = extra.get("headers")
    if isinstance(headers, dict) and headers:
        opts["headers"] = headers

    return opts


def mihomo_transport_options(proxy: dict, q: dict, protocol: str):
    """Apply only transport fields that Mihomo documents for the protocol."""
    network = (q1(q, "type", "tcp") or "tcp").lower()

    if network in {"tcp", "raw", "none"}:
        proxy["network"] = "tcp"
        return proxy

    if network == "ws":
        proxy["network"] = "ws"
        opts = {"path": unquote(q1(q, "path", "/"))}
        host = q1(q, "host", "")
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
        return proxy

    if network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {
            "grpc-service-name": q1(q, "serviceName", q1(q, "service_name", "")),
        }
        return proxy

    if network == "httpupgrade":
        # Mihomo exposes V2Ray HTTP Upgrade through ws-opts.
        proxy["network"] = "ws"
        opts = {
            "path": unquote(q1(q, "path", "/")),
            "v2ray-http-upgrade": True,
        }
        host = q1(q, "host", "")
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
        return proxy

    if network == "http":
        if protocol not in {"vless", "vmess"}:
            raise ValueError(f"Mihomo {protocol} does not support http transport")
        proxy["network"] = "http"
        path = unquote(q1(q, "path", "/"))
        opts = {"path": [path]}
        host = q1(q, "host", "")
        if host:
            opts["headers"] = {"Host": [host]}
        proxy["http-opts"] = opts
        return proxy

    if network in {"h2", "http2"}:
        if protocol not in {"vless", "vmess"}:
            raise ValueError(f"Mihomo {protocol} does not support h2 transport")
        proxy["network"] = "h2"
        opts = {"path": unquote(q1(q, "path", "/"))}
        host = q1(q, "host", "")
        if host:
            opts["host"] = [host]
        proxy["h2-opts"] = opts
        return proxy

    if network == "xhttp":
        if protocol != "vless":
            raise ValueError("Mihomo xhttp transport is supported for VLESS only")
        proxy["network"] = "xhttp"
        opts = {
            "path": unquote(q1(q, "path", "/")),
            "host": q1(q, "host", ""),
            "mode": q1(q, "mode", "auto"),
        }
        opts.update(_xhttp_extra_to_mihomo(q))
        proxy["xhttp-opts"] = opts
        return proxy

    raise ValueError(f"unsupported Mihomo transport: {network}")



def _apply_mihomo_tls_fields(proxy: dict, q: dict, *, sni_key: str = "servername"):
    sni = q1(q, "sni", "")
    if sni:
        proxy[sni_key] = sni

    alpn = split_csv(q1(q, "alpn", ""))
    if alpn:
        proxy["alpn"] = alpn

    fp = q1(q, "fp", "")
    if fp:
        proxy["client-fingerprint"] = fp

    if qbool(q, "insecure", "allowInsecure"):
        proxy["skip-cert-verify"] = True


def mihomo_proxy_from_uri(uri: str, name: str):
    """Convert a tested URI into a Mihomo proxy without dropping required fields."""
    p = urlsplit(uri)
    q = parse_qs(p.query, keep_blank_values=True)
    scheme = p.scheme.lower()

    if scheme == "vless":
        proxy = {
            "name": name,
            "type": "vless",
            "server": p.hostname,
            "port": p.port,
            "uuid": unquote(p.username or ""),
            "udp": True,
        }

        flow = q1(q, "flow", "")
        if flow:
            proxy["flow"] = flow

        packet_encoding = q1(q, "packetEncoding", q1(q, "packet-encoding", ""))
        if packet_encoding and packet_encoding.lower() != "none":
            proxy["packet-encoding"] = packet_encoding

        encryption = q1(q, "encryption", "")
        if encryption and encryption.lower() != "none":
            proxy["encryption"] = encryption

        security = (q1(q, "security", "") or "").lower()
        if security in {"tls", "reality"}:
            proxy["tls"] = True
            _apply_mihomo_tls_fields(proxy, q, sni_key="servername")

        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": q1(q, "pbk", ""),
                "short-id": q1(q, "sid", ""),
            }

        return mihomo_transport_options(proxy, q, "vless")

    if scheme == "trojan":
        proxy = {
            "name": name,
            "type": "trojan",
            "server": p.hostname,
            "port": p.port,
            "password": uri_userinfo(uri),
            "udp": True,
        }
        _apply_mihomo_tls_fields(proxy, q, sni_key="sni")

        security = (q1(q, "security", "") or "").lower()
        if security == "reality" or q1(q, "pbk", ""):
            proxy["reality-opts"] = {
                "public-key": q1(q, "pbk", ""),
                "short-id": q1(q, "sid", ""),
            }

        return mihomo_transport_options(proxy, q, "trojan")

    if scheme == "vmess":
        o = parse_vmess_uri(uri)
        proxy = {
            "name": name,
            "type": "vmess",
            "server": o.get("add"),
            "port": int(o.get("port")),
            "uuid": o.get("id"),
            "alterId": int(o.get("aid", 0) or 0),
            "cipher": o.get("scy", "auto"),
            "udp": True,
        }

        tls_enabled = str(o.get("tls", "")).lower() == "tls"
        if tls_enabled:
            proxy["tls"] = True
            if o.get("sni"):
                proxy["servername"] = o.get("sni")
            alpn = split_csv(o.get("alpn", ""))
            if alpn:
                proxy["alpn"] = alpn
            if o.get("fp"):
                proxy["client-fingerprint"] = o.get("fp")
            insecure_value = str(
                o.get(
                    "allowInsecure",
                    o.get("insecure", o.get("skip-cert-verify", "0")),
                )
            ).lower()
            if insecure_value in {"1", "true", "yes", "on"}:
                proxy["skip-cert-verify"] = True

        packet_encoding = o.get("packetEncoding") or o.get("packet-encoding")
        if packet_encoding and str(packet_encoding).lower() != "none":
            proxy["packet-encoding"] = packet_encoding

        fake_q = {
            "type": [o.get("net", "tcp")],
            "path": [o.get("path", "")],
            "host": [o.get("host", "")],
            "serviceName": [o.get("serviceName", o.get("service_name", ""))],
            "mode": [o.get("mode", "auto")],
        }
        return mihomo_transport_options(proxy, fake_q, "vmess")

    if scheme == "ss":
        method, password, host, port = parse_ss_uri(uri)
        return {
            "name": name,
            "type": "ss",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }

    if scheme in {"hy2", "hysteria2"}:
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": p.hostname,
            "port": p.port,
            "password": uri_userinfo(uri),
            "sni": q1(q, "sni", p.hostname or ""),
            "skip-cert-verify": qbool(q, "insecure", "allowInsecure"),
            "udp": True,
        }

        obfs = q1(q, "obfs", "")
        if obfs:
            proxy["obfs"] = obfs
            proxy["obfs-password"] = q1(q, "obfs-password", q1(q, "obfs_password", ""))

        alpn = split_csv(q1(q, "alpn", ""))
        if alpn:
            proxy["alpn"] = alpn

        up = q1(q, "upmbps", "")
        down = q1(q, "downmbps", "")
        if up:
            proxy["up"] = f"{up} Mbps" if re.fullmatch(r"\d+(?:\.\d+)?", up) else up
        if down:
            proxy["down"] = f"{down} Mbps" if re.fullmatch(r"\d+(?:\.\d+)?", down) else down

        ports = q1(q, "ports", q1(q, "mport", ""))
        if ports:
            proxy["ports"] = ports

        hop = q1(q, "hop-interval", q1(q, "hop_interval", ""))
        if hop:
            try:
                proxy["hop-interval"] = int(hop)
            except ValueError:
                proxy["hop-interval"] = hop

        return proxy

    raise ValueError(f"unsupported mihomo protocol: {scheme}")


def resolve_mihomo_binary() -> str:
    """Resolve the Mihomo executable used for both native delay-test stages."""
    explicit = os.getenv("MIHOMO_BINARY", "").strip()
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend((BIN_DIR / "mihomo", BIN_DIR / "mihomo.exe"))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    path_binary = shutil.which("mihomo")
    if path_binary:
        return path_binary

    raise FileNotFoundError(
        "Mihomo binary not found. Put it at bin/mihomo (or bin/mihomo.exe) "
        "or set MIHOMO_BINARY. Preliminary filtering and publication ranking "
        "require real Mihomo delay tests."
    )


def _read_mihomo_group_delay(controller_port: int, group_name: str):
    params = urlencode({
        "url": MIHOMO_PING_TEST_URL,
        "timeout": MIHOMO_PING_TIMEOUT_MS,
    })
    endpoint = (
        f"http://127.0.0.1:{controller_port}/group/"
        f"{quote(group_name, safe='')}/delay?{params}"
    )
    request = Request(
        endpoint,
        headers={"Accept": "application/json", "User-Agent": "VPN-Subscription-Builder/0.3"},
    )
    http_timeout = max(10.0, MIHOMO_PING_TIMEOUT_MS / 1000 + 10.0)
    # Do not let HTTP_PROXY/HTTPS_PROXY environment variables intercept the
    # localhost Mihomo controller request.
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=http_timeout) as response:
        payload = json.loads(response.read().decode("utf-8", errors="strict"))
    if not isinstance(payload, dict):
        raise RuntimeError("Mihomo group delay API returned a non-object response")
    return payload


async def measure_nodes_with_mihomo(
    nodes,
    *,
    stage: str,
    latency_key: str,
    error_key: str,
    sort_by_delay: bool = False,
):
    """Run one native Mihomo group delay-test over the supplied nodes.

    A node passes this stage only when Mihomo itself returns a positive delay.
    The same Cloudflare URL and timeout are used by the preliminary and final
    stages. The preliminary stage is an admission filter; the final stage is
    also the sole source of the publication ordering metric.
    """
    nodes = list(nodes)
    stage_slug = re.sub(r"[^A-Za-z0-9_-]+", "-", stage).strip("-") or "ping"
    stats = {
        "stage": stage,
        "test_url": MIHOMO_PING_TEST_URL,
        "timeout_ms": MIHOMO_PING_TIMEOUT_MS,
        "candidates": len(nodes),
        "converted": 0,
        "conversion_failed": 0,
        "measured": 0,
        "measurement_failed": 0,
    }
    if not nodes:
        return [], stats, []

    mihomo_binary = resolve_mihomo_binary()
    stats["binary"] = mihomo_binary
    controller_port = free_port()
    mixed_port = free_port()
    group_name = f"MIHOMO-{stage_slug.upper()}"

    proxies = []
    name_to_item = {}
    errors = []

    for index, item in enumerate(nodes, start=1):
        node_name = f"{stage_slug}-{index:06d}"
        item[latency_key] = None
        item[error_key] = None
        try:
            proxy = mihomo_proxy_from_uri(item["uri"], node_name)
        except Exception as e:
            error = f"conversion: {type(e).__name__}: {e}"
            item[error_key] = error
            errors.append({
                "name": node_name,
                "protocol": item["uri"].split("://", 1)[0].lower(),
                "error": error,
            })
            continue
        proxies.append(proxy)
        name_to_item[node_name] = item

    stats["converted"] = len(proxies)
    stats["conversion_failed"] = len(nodes) - len(proxies)

    if not proxies:
        return [], stats, errors

    config = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": proxies,
        "proxy-groups": [{
            "name": group_name,
            "type": "select",
            "proxies": [proxy["name"] for proxy in proxies],
        }],
        "rules": [f"MATCH,{group_name}"],
    }

    process = None
    delays = {}
    with tempfile.TemporaryDirectory(prefix=f"mihomo-{stage_slug}-") as tmpdir:
        cfg_file = Path(tmpdir) / "config.yaml"
        stderr_file = Path(tmpdir) / "mihomo.stderr.log"
        cfg_file.write_text(yaml_dump(config), encoding="utf-8")

        try:
            with stderr_file.open("wb") as stderr_stream:
                process = await asyncio.create_subprocess_exec(
                    mihomo_binary,
                    "-d",
                    tmpdir,
                    "-f",
                    str(cfg_file),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=stderr_stream,
                )

            if not await wait_port(controller_port, timeout=MIHOMO_START_TIMEOUT):
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2)
                    except Exception:
                        process.kill()
                        await process.wait()
                try:
                    stderr_text = stderr_file.read_text(encoding="utf-8", errors="replace")[-1200:]
                except Exception:
                    stderr_text = ""
                raise RuntimeError(
                    f"Mihomo controller did not start for {stage}"
                    + (f": {stderr_text}" if stderr_text else "")
                )

            delays = await asyncio.to_thread(
                _read_mihomo_group_delay,
                controller_port,
                group_name,
            )

        finally:
            if process is not None and process.returncode is None:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=2)
                except Exception:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

    passed = []
    for node_name, item in name_to_item.items():
        raw_delay = delays.get(node_name)
        try:
            delay = float(raw_delay)
        except (TypeError, ValueError):
            delay = 0.0

        if delay <= 0:
            error = "measurement: Mihomo returned no positive delay"
            item[error_key] = error
            errors.append({
                "name": node_name,
                "protocol": item["uri"].split("://", 1)[0].lower(),
                "error": error,
            })
            continue

        rounded_delay = round(delay, 1)
        item[latency_key] = rounded_delay
        item[error_key] = None
        passed.append(item)

    if sort_by_delay:
        passed.sort(key=lambda item: item[latency_key])

    stats["measured"] = len(passed)
    stats["measurement_failed"] = len(proxies) - len(passed)
    return passed, stats, errors



def _source_display_name(uri: str):
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            name = str(parse_vmess_uri(uri).get("ps") or "").strip()
            if name:
                return name
        else:
            fragment = urlsplit(uri).fragment
            if fragment:
                name = unquote(fragment).strip()
                if name:
                    return name
    except Exception:
        pass
    return None


def _fallback_display_name(uri: str, index: int, country: str | None = None):
    scheme = uri.split("://", 1)[0].lower()
    host = extract_server_host(uri) or f"node-{index}"
    port = None
    try:
        if scheme == "vmess":
            port = parse_vmess_uri(uri).get("port")
        elif scheme == "ss":
            _, _, _, port = parse_ss_uri(uri)
        else:
            port = urlsplit(uri).port
    except Exception:
        pass

    endpoint = f"{host}:{port}" if port else host
    base = f"{scheme.upper()} | {endpoint}"
    return f"{country} | {base}" if country else base


def _sanitize_proxy_name(name: str):
    name = re.sub(r"[\x00-\x1f\x7f]+", " ", str(name))
    name = re.sub(r"\s+", " ", name).strip()
    return name[:160] or "VPN node"


def write_mihomo_files(nodes):
    """
    Create the Mihomo proxy-provider and client configuration.

    In GitHub Actions (or when MIHOMO_PROVIDER_URL is explicitly supplied),
    mihomo.yaml uses the remote HTTP provider. The provider refreshes every
    5 minutes, while Mihomo itself health-checks provider nodes every 60 seconds
    through Cloudflare. AUTO selects among those provider nodes with 30 ms
    switching tolerance.

    For local runs without a provider URL, keep a directly usable embedded
    config instead of emitting a broken remote-provider reference.
    Source-provided names are preserved first; country lookup is fallback-only.
    """
    OUT_DIR.mkdir(exist_ok=True)

    proxies = []
    skipped = 0
    conversion_errors = []
    used_names = {}

    for index, item in enumerate(nodes, start=1):
        uri = item["uri"]
        base_name = _source_display_name(uri)
        if not base_name:
            country = item.get("country")
            if not country:
                country = detect_country_label_from_host(extract_server_host(uri))
            base_name = _fallback_display_name(uri, index, country)

        base_name = _sanitize_proxy_name(base_name)
        count = used_names.get(base_name, 0) + 1
        used_names[base_name] = count
        node_name = base_name if count == 1 else f"{base_name} [{count}]"

        try:
            proxies.append(mihomo_proxy_from_uri(uri, node_name))
        except Exception as e:
            skipped += 1
            conversion_errors.append({
                "name": node_name,
                "protocol": uri.split("://", 1)[0].lower(),
                "error": f"{type(e).__name__}: {e}",
            })

    mihomo_provider = {"proxies": proxies}
    (OUT_DIR / "mihomo-provider.yaml").write_text(
        yaml_dump(mihomo_provider),
        encoding="utf-8",
    )

    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    branch = os.getenv("GITHUB_REF_NAME", "main").strip() or "main"
    provider_url = os.getenv("MIHOMO_PROVIDER_URL", "").strip()

    if not provider_url and repository:
        provider_url = (
            f"https://raw.githubusercontent.com/{repository}/{branch}/"
            "output/mihomo-provider.yaml"
        )

    if provider_url:
        # Remote/provider mode used by the published GitHub configuration.
        # Provider download cadence and node health-check cadence are separate.
        mihomo_config = {
            "mixed-port": 7890,
            "mode": "rule",
            "proxy-providers": {
                "VPN": {
                    "type": "http",
                    "url": provider_url,
                    "path": "./providers/vpn.yaml",
                    "interval": 300,
                    "health-check": {
                        "enable": True,
                        "url": MIHOMO_AUTO_TEST_URL,
                        "interval": 60,
                        "timeout": 5000,
                        "lazy": False,
                    },
                },
            },
            "proxy-groups": [{
                "name": "AUTO",
                "type": "url-test",
                "use": ["VPN"],
                "tolerance": 30,
            }],
            "rules": ["MATCH,AUTO"],
        }
    else:
        # Local fallback: no remote provider URL exists, so test the embedded
        # proxies directly. This preserves the same 60-second client-side AUTO
        # behavior without inventing a URL that cannot work locally.
        mihomo_config = {
            "mixed-port": 7890,
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": [{
                "name": "AUTO",
                "type": "url-test",
                "proxies": [x["name"] for x in proxies],
                "url": MIHOMO_AUTO_TEST_URL,
                "interval": 60,
                "timeout": 5000,
                "tolerance": 30,
                "lazy": False,
            }],
            "rules": ["MATCH,AUTO"],
        }

    (OUT_DIR / "mihomo.yaml").write_text(
        yaml_dump(mihomo_config),
        encoding="utf-8",
    )

    return len(proxies), skipped, conversion_errors



def yaml_dump(data):
    """
    Small dependency-free YAML serializer.

    All strings are emitted as JSON-style quoted scalars (valid YAML), which
    safely handles empty strings, booleans-looking strings, emoji, backslashes
    and control characters.
    """
    def scalar(value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return json.dumps(str(value), ensure_ascii=False)

    def dump(obj, indent=0):
        pad = " " * indent

        if isinstance(obj, dict):
            if not obj:
                return f"{pad}{{}}"
            result = []
            for key, value in obj.items():
                if isinstance(value, dict):
                    if value:
                        result.append(f"{pad}{key}:")
                        result.append(dump(value, indent + 2))
                    else:
                        result.append(f"{pad}{key}: {{}}")
                elif isinstance(value, list):
                    if value:
                        result.append(f"{pad}{key}:")
                        result.append(dump(value, indent + 2))
                    else:
                        result.append(f"{pad}{key}: []")
                else:
                    result.append(f"{pad}{key}: {scalar(value)}")
            return "\n".join(result)

        if isinstance(obj, list):
            if not obj:
                return f"{pad}[]"
            result = []
            for item in obj:
                if isinstance(item, dict):
                    if item:
                        result.append(f"{pad}-")
                        result.append(dump(item, indent + 2))
                    else:
                        result.append(f"{pad}- {{}}")
                elif isinstance(item, list):
                    if item:
                        result.append(f"{pad}-")
                        result.append(dump(item, indent + 2))
                    else:
                        result.append(f"{pad}- []")
                else:
                    result.append(f"{pad}- {scalar(item)}")
            return "\n".join(result)

        return f"{pad}{scalar(obj)}"

    return dump(data) + "\n"


async def safe_probe(uri: str, probe_stats: dict):
    """
    Full VPN probe wrapper.

    Starts the temporary Xray/sing-box tunnel and runs the existing mandatory
    service cascade. Geography and preliminary DNS latency filters are disabled.
    Any exception means the node fails immediately.
    """
    async with VPN_PROCESS_SEMAPHORE:
        try:
            return await run_probe(uri, probe_stats)
        except Exception as e:
            return Probe(
                False,
                error=f"{type(e).__name__}: {e}",
            )




async def main():
    run_started = time.monotonic()
    OUT_DIR.mkdir(exist_ok=True)
    STATE_FILE.parent.mkdir(exist_ok=True)

    global CHEAP_PROBE_SEMAPHORE
    global VPN_PROCESS_SEMAPHORE

    CHEAP_PROBE_SEMAPHORE = asyncio.Semaphore(CHECK_CONCURRENCY)
    VPN_PROCESS_SEMAPHORE = asyncio.Semaphore(VPN_PROCESS_CONCURRENCY)

    source_nodes, source_stats, duplicates = collect_sources()
    old = load_state()
    now = int(time.time())

    source_protocol_stats = {}
    for uri in source_nodes.values():
        scheme = uri.split("://", 1)[0].lower()
        source_protocol_stats[scheme] = source_protocol_stats.get(scheme, 0) + 1

    # state.json is only a candidate memory. Old and new nodes are equal.
    candidates = dict(source_nodes)
    state_candidates_with_uri = 0
    for _, item in old.items():
        uri = item.get("uri") if isinstance(item, dict) else None
        if not uri:
            continue
        state_candidates_with_uri += 1
        candidates.setdefault(canonical(uri), uri)

    # This is the true source+state pool size before cross-pool deduplication.
    merged_candidates_before_dedup = len(source_nodes) + state_candidates_with_uri

    # Deduplicate the complete pool without changing any operational URI field.
    merged = {}
    for uri in candidates.values():
        merged.setdefault(canonical(uri), uri)

    merged_protocol_stats = {}
    for uri in merged.values():
        scheme = uri.split("://", 1)[0].lower()
        merged_protocol_stats[scheme] = merged_protocol_stats.get(scheme, 0) + 1

    # Every deduplicated candidate first enters the native Mihomo precheck.
    # Only survivors get an Xray/sing-box tunnel and proceed to the service
    # cascade. Geography and preliminary DNS latency filters remain disabled.
    current = {}
    for key, uri in merged.items():
        country = None
        if not _source_display_name(uri):
            country = detect_country_label_from_host(extract_server_host(uri))
        current[key] = {
            "uri": uri,
            "country": country,
            "mihomo_precheck_latency_ms": None,
            "mihomo_precheck_error": None,
            "cascade_latency_ms": None,
            "mihomo_final_latency_ms": None,
            "mihomo_final_error": None,
            "last_latency_ms": None,
            "last_error": None,
        }

    # First native Mihomo delay-test: remove dead/unmeasurable nodes before
    # spending time on the expensive mandatory service cascade.
    precheck_candidates = list(current.values())
    mihomo_prepassed, mihomo_precheck_stats, mihomo_precheck_errors = (
        await measure_nodes_with_mihomo(
            precheck_candidates,
            stage="precheck",
            latency_key="mihomo_precheck_latency_ms",
            error_key="mihomo_precheck_error",
            sort_by_delay=False,
        )
    )
    prepassed_keys = {canonical(item["uri"]) for item in mihomo_prepassed}
    current = {
        key: item
        for key, item in current.items()
        if key in prepassed_keys
    }

    probe_stats = {
        name: {"checked": 0, "passed": 0, "failed": 0}
        for name in (
            "chatgpt",
            "chatgpt_auth_tls",
            "chatgpt_android_tls",
            "youtube_204",
            "telegram_https",
            "telegram_mtproto",
            "whatsapp_core",
            "instagram_https",
        )
    }

    keys = list(current.keys())
    results = await asyncio.gather(
        *(safe_probe(current[k]["uri"], probe_stats) for k in keys)
    )

    deleted = 0
    successes = 0
    failures = 0
    failure_samples = []

    for key, result in zip(keys, results):
        if result.ok:
            successes += 1
            current[key]["cascade_latency_ms"] = result.latency_ms
            current[key]["last_error"] = None
        else:
            failures += 1
            if len(failure_samples) < 20:
                failure_samples.append({
                    "protocol": current[key]["uri"].split("://", 1)[0].lower(),
                    "error": result.error,
                })
            del current[key]
            deleted += 1

    # Second native Mihomo delay-test: every cascade-verified node is measured
    # again from scratch. Only THIS final Mihomo delay determines publication order.
    cascade_verified = list(current.values())
    mihomo_final_ranked, mihomo_final_stats, mihomo_final_errors = (
        await measure_nodes_with_mihomo(
            cascade_verified,
            stage="final",
            latency_key="mihomo_final_latency_ms",
            error_key="mihomo_final_error",
            sort_by_delay=True,
        )
    )
    for item in mihomo_final_ranked:
        item["last_latency_ms"] = item["mihomo_final_latency_ms"]

    published_ordered = mihomo_final_ranked[:MAX_PUBLISHED_NODES]

    (OUT_DIR / "subscription.txt").write_text(
        "\n".join(x["uri"] for x in published_ordered)
        + ("\n" if published_ordered else ""),
        encoding="utf-8",
    )

    mihomo_nodes, mihomo_skipped, conversion_errors = write_mihomo_files(
        published_ordered
    )

    # Keep all nodes that passed the preliminary Mihomo filter and mandatory
    # service cascade in state.json. All eligible nodes are published; nodes whose final Mihomo ping failed
    # can compete again from scratch on the next refresh.
    STATE_FILE.write_text(
        json.dumps({"updated_at": now, "nodes": current}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    protocol_stats = {}
    for item in published_ordered:
        scheme = item["uri"].split("://", 1)[0].lower()
        protocol_stats[scheme] = protocol_stats.get(scheme, 0) + 1

    duration = round(time.monotonic() - run_started, 2)

    # Precheck survivors that never reached ChatGPT failed while starting the
    # Xray/sing-box engine/config/SOCKS tunnel.
    engine_failed_before_checks = len(keys) - probe_stats["chatgpt"]["checked"]

    status = {
        "updated_at": now,
        "source_nodes_unique": len(source_nodes),
        "source_duplicates_removed": duplicates,
        "source_stats": source_stats,
        "source_protocol_stats": source_protocol_stats,
        "state_nodes_loaded": len(old),
        "merged_candidates_before_dedup": merged_candidates_before_dedup,
        "merged_candidates_after_dedup": len(merged),
        "merged_duplicates_removed": merged_candidates_before_dedup - len(merged),
        "candidate_dedup_policy": "conservative effective configuration; fp/fingerprint and unknown operational fields are significant; display name/fragment and query order are cosmetic; VLESS omitted encryption/security normalize to none; repeated query fields are kept conservatively distinct",
        "geography_policy": "disabled; geography is not checked and never affects admission",
        "merged_protocol_stats": merged_protocol_stats,
        "initial_mihomo_precheck_candidates": len(precheck_candidates),
        "initial_mihomo_precheck_passed": len(mihomo_prepassed),
        "initial_mihomo_precheck_rejected": len(precheck_candidates) - len(mihomo_prepassed),
        "checked_this_run": len(keys),
        "vpn_engine_failed_before_checks": engine_failed_before_checks,
        "successful_this_run": successes,
        "failed_this_run": failures,
        "rejected_this_run": deleted,
        "cascade_verified_nodes": len(cascade_verified),
        "verified_nodes_before_publish_cap": len(mihomo_final_ranked),
        "mihomo_final_eligible_nodes": len(mihomo_final_ranked),
        "mihomo_final_failed_nodes": len(cascade_verified) - len(mihomo_final_ranked),
        "publish_limit": MAX_PUBLISHED_NODES,
        "not_published_due_to_limit": max(
            0,
            len(mihomo_final_ranked) - len(published_ordered),
        ),
        "ranking_policy": (
            "Mihomo first removes nodes with no positive Cloudflare delay before "
            "the service cascade. After every mandatory service probe has passed, "
            "Mihomo measures the survivors again. Publish all eligible nodes with the "
            "lowest FINAL Mihomo delay; preliminary and service-probe latency are "
            "not used for publication ordering"
        ),
        "mihomo_precheck": mihomo_precheck_stats,
        "mihomo_precheck_errors": mihomo_precheck_errors[:50],
        "mihomo_final_ping": mihomo_final_stats,
        "mihomo_final_ping_errors": mihomo_final_errors[:50],
        "published_nodes": len(published_ordered),
        "mihomo_nodes": mihomo_nodes,
        "mihomo_skipped": mihomo_skipped,
        "mihomo_output_warning": (
            "Mihomo output differs from published nodes"
            if mihomo_nodes != len(published_ordered)
            else None
        ),
        "output_validation": {
            "published_nodes": len(published_ordered),
            "mihomo_nodes": mihomo_nodes,
            "published_equals_mihomo": mihomo_nodes == len(published_ordered),
            "conversion_failed": mihomo_skipped,
            "conversion_errors": conversion_errors,
        },
        "protocol_stats": protocol_stats,
        "probe_stats": probe_stats,
        "probe_policy": {
            "chatgpt": f"exact HTTP 200; quality <= {QUALITY_MAX_SECONDS:g}s",
            "whatsapp_core": (
                "e1/e2 checked in parallel; ports 443/5222 checked in parallel "
                f"per endpoint; e3 only if needed; require 2 of 3 endpoints; "
                f"timeout {WHATSAPP_PROBE_TIMEOUT:g}s per endpoint stage"
            ),
            "instagram_https": (
                "mandatory availability gate through VPN; any real HTTPS response "
                "from www.instagram.com passes; TLS/connect/timeout/no HTTP response fails; "
                "latency does not affect publication ranking"
            ),
            "mihomo_precheck": (
                "pre-cascade native Mihomo group delay test; test URL "
                f"{MIHOMO_PING_TEST_URL}; timeout {MIHOMO_PING_TIMEOUT_MS} ms; "
                "nodes without a positive delay are rejected before the cascade"
            ),
            "mihomo_final_ping": (
                "post-cascade native Mihomo group delay test against the same "
                f"Cloudflare URL {MIHOMO_PING_TEST_URL}; timeout "
                f"{MIHOMO_PING_TIMEOUT_MS} ms; ascending FINAL delay is the sole "
                "publication ranking metric"
            ),
        },
        "failure_samples": failure_samples,
        "run_statistics": {
            "precheck_candidates": len(precheck_candidates),
            "precheck_passed_nodes": len(mihomo_prepassed),
            "checked_nodes": len(keys),
            "cascade_verified_nodes": len(cascade_verified),
            "final_mihomo_ranked_nodes": len(mihomo_final_ranked),
            "published_nodes": len(published_ordered),
            "duration_seconds": duration,
        },
        "run_duration_seconds": duration,
        "admission_rule": "Geography and preliminary DNS latency filters are disabled. Every deduplicated candidate is first tested by Mihomo itself against Cloudflare; no positive delay means immediate rejection before the service cascade. Survivors must then pass every mandatory service probe. After the cascade, Mihomo performs a second fresh Cloudflare delay test. Only nodes with a positive FINAL Mihomo delay are eligible for publication, and all eligible nodes are ordered strictly by that final delay.",
        "note": "Node age does not matter. Previous nodes and new nodes are treated equally on every run. Preliminary Mihomo latency is only a dead-node filter. Service-probe latency is admission telemetry only. Final Mihomo latency is the sole publication ordering metric. Client AUTO uses the same Cloudflare test URL.",
    }

    (OUT_DIR / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
