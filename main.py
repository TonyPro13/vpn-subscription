from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import struct
import tempfile
import time
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit
from urllib.request import Request, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
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

MIHOMO_AUTO_TEST_URL = "https://cp.cloudflare.com"

# Mandatory pre-service network quality filter.
# Each resolver is tested with a real DNS-over-TCP query through the already
# established local SOCKS5 tunnel. The measured latency covers only the DNS
# request/response after the SOCKS CONNECT has succeeded, which is the closest
# SOCKS-compatible analogue of endpoint RTT.
NETWORK_PREFILTER_MAX_MS = 200.0
NETWORK_PREFILTER_CONNECT_TIMEOUT = 5.0
NETWORK_PREFILTER_RESPONSE_TIMEOUT = 1.0
NETWORK_PREFILTER_QUERY_NAME = "example.com"
NETWORK_PREFILTER_TARGETS = (
    ("cloudflare_1111", "1.1.1.1"),
    ("google_8888", "8.8.8.8"),
)

QUALITY_MAX_SECONDS = float(os.getenv("QUALITY_MAX_SECONDS", "5"))

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


def _build_dns_query(name: str):
    labels = [label.encode("idna") for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise ValueError("DNS query name is empty")

    qname = bytearray()
    for label in labels:
        if len(label) > 63:
            raise ValueError("DNS label is too long")
        qname.append(len(label))
        qname.extend(label)
    qname.append(0)

    txid = secrets.randbits(16)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = bytes(qname) + struct.pack("!HH", 1, 1)  # A / IN
    return txid, header + question


async def _read_socks5_address(reader: asyncio.StreamReader, atyp: int, timeout: float):
    if atyp == 0x01:  # IPv4
        await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    elif atyp == 0x03:  # domain
        size = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
        await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
    elif atyp == 0x04:  # IPv6
        await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
    else:
        raise ValueError(f"SOCKS5 returned unsupported address type: {atyp}")

    await asyncio.wait_for(reader.readexactly(2), timeout=timeout)


async def dns_tcp_latency_via_socks(
    socks_port: int,
    resolver_ip: str,
):
    """
    Run one real DNS-over-TCP A query through the node's local SOCKS5 tunnel.

    Connection establishment is required to succeed but is intentionally not
    included in the latency value. Timing starts immediately before the DNS
    query is sent and stops after the complete DNS response is received.
    """
    reader = None
    writer = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", socks_port),
            timeout=NETWORK_PREFILTER_CONNECT_TIMEOUT,
        )

        writer.write(b"\x05\x01\x00")
        await writer.drain()
        greeting = await asyncio.wait_for(
            reader.readexactly(2),
            timeout=NETWORK_PREFILTER_CONNECT_TIMEOUT,
        )
        if greeting != b"\x05\x00":
            raise ConnectionError(
                f"SOCKS5 greeting failed: {greeting.hex()}"
            )

        target = ipaddress.ip_address(resolver_ip)
        atyp = b"\x01" if target.version == 4 else b"\x04"

        request = (
            b"\x05\x01\x00"
            + atyp
            + target.packed
            + struct.pack("!H", 53)
        )
        writer.write(request)
        await writer.drain()

        reply = await asyncio.wait_for(
            reader.readexactly(4),
            timeout=NETWORK_PREFILTER_CONNECT_TIMEOUT,
        )
        if reply[0] != 0x05:
            raise ConnectionError(
                f"SOCKS5 invalid reply version: {reply[0]}"
            )
        if reply[1] != 0x00:
            raise ConnectionError(
                f"SOCKS5 CONNECT failed with code 0x{reply[1]:02x}"
            )
        await _read_socks5_address(
            reader,
            reply[3],
            NETWORK_PREFILTER_CONNECT_TIMEOUT,
        )

        txid, query = _build_dns_query(NETWORK_PREFILTER_QUERY_NAME)
        framed_query = struct.pack("!H", len(query)) + query

        started = time.perf_counter()
        writer.write(framed_query)
        await writer.drain()

        length_raw = await asyncio.wait_for(
            reader.readexactly(2),
            timeout=NETWORK_PREFILTER_RESPONSE_TIMEOUT,
        )
        response_length = struct.unpack("!H", length_raw)[0]
        if response_length < 12:
            raise ValueError(
                f"DNS response is too short: {response_length} bytes"
            )

        response = await asyncio.wait_for(
            reader.readexactly(response_length),
            timeout=NETWORK_PREFILTER_RESPONSE_TIMEOUT,
        )
        latency_ms = (time.perf_counter() - started) * 1000.0

        response_txid, flags = struct.unpack("!HH", response[:4])
        if response_txid != txid:
            raise ValueError("DNS response transaction ID mismatch")
        if not (flags & 0x8000):
            raise ValueError("DNS packet is not a response")

        rcode = flags & 0x000F
        if rcode != 0:
            raise ValueError(f"DNS resolver returned RCODE={rcode}")

        return round(latency_ms, 1)

    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def network_prefilter_probe(
    port: int,
    network_prefilter_stats: dict,
):
    """
    Mandatory cascade before the existing service cascade:

      1.1.1.1 DNS-over-TCP latency <= 200 ms
      8.8.8.8 DNS-over-TCP latency <= 200 ms

    The second target is checked only if the first target passes.
    """
    for name, resolver_ip in NETWORK_PREFILTER_TARGETS:
        stats = network_prefilter_stats[name]
        stats["checked"] += 1

        try:
            async with CHEAP_PROBE_SEMAPHORE:
                latency_ms = await dns_tcp_latency_via_socks(
                    port,
                    resolver_ip,
                )
        except Exception as e:
            stats["failed"] += 1
            return Probe(
                False,
                error=(
                    f"{name}: DNS-over-TCP check failed: "
                    f"{type(e).__name__}: {e}"
                ),
            )

        if latency_ms > NETWORK_PREFILTER_MAX_MS:
            stats["failed"] += 1
            return Probe(
                False,
                latency_ms=latency_ms,
                error=(
                    f"{name}: too slow "
                    f"({latency_ms:.1f}ms > {NETWORK_PREFILTER_MAX_MS:.0f}ms)"
                ),
            )

        stats["passed"] += 1
        stats["latency_sum_ms"] += latency_ms
        stats["latency_samples"] += 1

    network_prefilter_stats["passed_both"] += 1
    return Probe(True)


async def quality_probe(
    port: int,
    probe_stats: dict,
):
    """Full mandatory cascade:
    ChatGPT (3 checks), YouTube, Telegram HTTPS, Telegram MTProto.
    Any failure rejects the node immediately.
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

    return Probe(
        True,
        latency_ms=round(sum(latencies) / len(latencies), 1) if latencies else None,
    )



async def run_probe(
    uri: str,
    probe_stats: dict,
    network_prefilter_stats: dict,
):
    """
    Creates a temporary VPN tunnel, requires both global DNS directions to
    respond within 200 ms, and only then runs the existing mandatory service
    cascade. Geography is not checked and never affects admission.
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

        # Two mandatory global network directions, both <= 200 ms.
        # They run before the existing ChatGPT/YouTube/Telegram cascade.
        network_result = await network_prefilter_probe(
            port,
            network_prefilter_stats,
        )
        if not network_result.ok:
            return network_result

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


async def safe_probe(
    uri: str,
    probe_stats: dict,
    network_prefilter_stats: dict,
):
    """
    Full VPN probe wrapper.

    Starts the temporary Xray/sing-box tunnel, runs the mandatory
    1.1.1.1 / 8.8.8.8 network prefilter, and only then runs the existing
    service cascade. Geography is not checked. Any exception means the node
    fails immediately.
    """
    async with VPN_PROCESS_SEMAPHORE:
        try:
            return await run_probe(
                uri,
                probe_stats,
                network_prefilter_stats,
            )
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

    # Every deduplicated candidate gets a real VPN tunnel. Admission is:
    # 1.1.1.1 <= 200 ms -> 8.8.8.8 <= 200 ms -> existing service cascade.
    # Geography is not checked and never rejects a candidate.
    current = {}
    for key, uri in merged.items():
        country = None
        if not _source_display_name(uri):
            country = detect_country_label_from_host(extract_server_host(uri))
        current[key] = {
            "uri": uri,
            "country": country,
            "last_latency_ms": None,
            "last_error": None,
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
        )
    }

    network_prefilter_stats = {
        "cloudflare_1111": {
            "checked": 0,
            "passed": 0,
            "failed": 0,
            "latency_sum_ms": 0.0,
            "latency_samples": 0,
        },
        "google_8888": {
            "checked": 0,
            "passed": 0,
            "failed": 0,
            "latency_sum_ms": 0.0,
            "latency_samples": 0,
        },
        "passed_both": 0,
    }

    keys = list(current.keys())
    results = await asyncio.gather(
        *(
            safe_probe(
                current[k]["uri"],
                probe_stats,
                network_prefilter_stats,
            )
            for k in keys
        )
    )

    deleted = 0
    successes = 0
    failures = 0
    failure_samples = []

    for key, result in zip(keys, results):
        if result.ok:
            successes += 1
            current[key]["last_latency_ms"] = result.latency_ms
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

    # Put the fastest successfully verified nodes first.
    # This changes only output order; admission checks and the published pool
    # remain exactly the same.
    ordered = sorted(
        current.values(),
        key=lambda x: (
            x["last_latency_ms"] is None,
            x["last_latency_ms"] if x["last_latency_ms"] is not None else float("inf"),
        ),
    )

    (OUT_DIR / "subscription.txt").write_text(
        "\n".join(x["uri"] for x in ordered) + ("\n" if ordered else ""),
        encoding="utf-8",
    )

    mihomo_nodes, mihomo_skipped, conversion_errors = write_mihomo_files(ordered)

    STATE_FILE.write_text(
        json.dumps({"updated_at": now, "nodes": current}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    protocol_stats = {}
    for item in ordered:
        scheme = item["uri"].split("://", 1)[0].lower()
        protocol_stats[scheme] = protocol_stats.get(scheme, 0) + 1

    duration = round(time.monotonic() - run_started, 2)

    for target_name in ("cloudflare_1111", "google_8888"):
        target_stats = network_prefilter_stats[target_name]
        samples = target_stats.pop("latency_samples")
        latency_sum = target_stats.pop("latency_sum_ms")
        target_stats["average_latency_ms"] = (
            round(latency_sum / samples, 1)
            if samples
            else None
        )

    # Candidates that never reached the first network probe failed while
    # starting the VPN engine/config/SOCKS tunnel.
    engine_failed_before_network_prefilter = (
        len(keys) - network_prefilter_stats["cloudflare_1111"]["checked"]
    )

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
        "checked_this_run": len(keys),
        "vpn_engine_failed_before_network_prefilter": engine_failed_before_network_prefilter,
        "network_prefilter_policy": {
            "transport": "real DNS-over-TCP via the node SOCKS5 tunnel",
            "query": NETWORK_PREFILTER_QUERY_NAME,
            "targets": ["1.1.1.1", "8.8.8.8"],
            "max_latency_ms_each": NETWORK_PREFILTER_MAX_MS,
            "requirement": "both targets must pass; cascade order 1.1.1.1 then 8.8.8.8",
        },
        "network_prefilter_stats": network_prefilter_stats,
        "service_candidates_after_network_prefilter": network_prefilter_stats["passed_both"],
        "successful_this_run": successes,
        "failed_this_run": failures,
        "rejected_this_run": deleted,
        "published_nodes": len(current),
        "mihomo_nodes": mihomo_nodes,
        "mihomo_skipped": mihomo_skipped,
        "mihomo_output_warning": (
            "Mihomo output differs from published nodes"
            if mihomo_nodes != len(ordered)
            else None
        ),
        "output_validation": {
            "published_nodes": len(ordered),
            "mihomo_nodes": mihomo_nodes,
            "published_equals_mihomo": mihomo_nodes == len(ordered),
            "conversion_failed": mihomo_skipped,
            "conversion_errors": conversion_errors,
        },
        "protocol_stats": protocol_stats,
        "probe_stats": probe_stats,
        "probe_policy": {
            "chatgpt": f"exact HTTP 200; quality <= {QUALITY_MAX_SECONDS:g}s",
        },
        "failure_samples": failure_samples,
        "run_statistics": {
            "checked_nodes": len(keys),
            "published_nodes": len(current),
            "duration_seconds": duration,
        },
        "run_duration_seconds": duration,
        "admission_rule": "Geography is not checked. A node must pass DNS-over-TCP latency checks to both 1.1.1.1 and 8.8.8.8 at <=200 ms each, then pass every existing mandatory service probe. Failure at any active stage rejects the node immediately.",
        "note": "Node age does not matter. Previous nodes and new nodes are treated equally on every run.",
    }

    (OUT_DIR / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
