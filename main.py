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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
]

RU_IPV4_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
RU_IPV6_URL = "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone"

SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
STATE_FILE = Path("data/state.json")
OUT_DIR = Path("output")
BIN_DIR = Path("bin")
XRAY = BIN_DIR / "xray"
SINGBOX = BIN_DIR / "sing-box"

CHEAP_PROBE_SEMAPHORE = None
VPN_PROCESS_SEMAPHORE = None

CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "20"))
VPN_PROCESS_CONCURRENCY = int(os.getenv("VPN_PROCESS_CONCURRENCY", "40"))
GEO_DNS_CONCURRENCY = int(os.getenv("GEO_DNS_CONCURRENCY", "32"))
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


def canonical(uri: str) -> str:
    """
    Normalize a VPN URI before expensive checks.

    Purpose:
    - remove cosmetic differences (fragment names, query order);
    - avoid checking the same node several times;
    - keep normalization conservative so different servers are not merged accidentally.
    """
    uri = uri.strip()
    try:
        scheme = uri.split("://", 1)[0].lower()
        if scheme == "vmess":
            return uri.split("#", 1)[0].strip()

        p = urlsplit(uri)
        host = (p.hostname or "").lower().rstrip(".")
        # www and case differences are cosmetic for host comparison only.
        netloc = host
        if p.port:
            netloc += f":{p.port}"
        q = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((p.scheme.lower(), netloc, p.path, q, ""))
    except Exception:
        return uri.split("#", 1)[0]


def clean_insecure_params(uri: str) -> str:
    uri = re.sub(r'(?i)(allowinsecure|insecure)=[^&]*', '', uri)
    uri = re.sub(r'(?i)([?&])packetEncoding=none(?=&|#|$)', r'\1', uri)
    uri = uri.replace("?&", "?")
    uri = re.sub(r'&&+', '&', uri)
    return uri
def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "VPN-Subscription-Builder/0.3"})
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def load_ru_networks():
    networks = []

    for url in (RU_IPV4_URL, RU_IPV6_URL):
        try:
            text = fetch(url)
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
        except Exception as e:
            print(f"WARNING: failed to load RU IP ranges from {url}: {e}")

    print(f"Loaded {len(networks)} Russian IP networks")
    return networks


def extract_server_host(uri: str):
    try:
        scheme = uri.split("://", 1)[0].lower()

        if scheme == "vmess":
            raw = uri.split("://", 1)[1].split("#", 1)[0]
            data = json.loads(b64decode(raw).decode("utf-8", errors="replace"))
            host = data.get("add")
            return str(host).strip() if host else None

        if scheme == "ss":
            raw = uri.split("://", 1)[1]
            raw = raw.split("#", 1)[0]
            raw = raw.split("?", 1)[0]

            if "@" in raw:
                server_part = raw.rsplit("@", 1)[1]
            else:
                decoded = b64decode(raw).decode("utf-8", errors="replace")
                if "@" not in decoded:
                    return None
                server_part = decoded.rsplit("@", 1)[1]

            parsed = urlsplit("ss://x@" + server_part)
            return parsed.hostname

        return urlsplit(uri).hostname

    except Exception:
        return None


def is_russian_host(host: str, ru_networks):
    try:
        try:
            ip = ipaddress.ip_address(host)
            ips = [ip]
        except ValueError:
            infos = socket.getaddrinfo(host, None)
            ips = []

            for info in infos:
                try:
                    ips.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    pass

        if not ips:
            return None

        for ip in ips:
            for network in ru_networks:
                if ip.version == network.version and ip in network:
                    return True

        return False

    except Exception:
        return None


def collect_sources():
    """
    Collect VPN candidates only.

    Important order:
    1. download sources;
    2. parse supported protocols;
    3. normalize and remove duplicates;
    4. return candidates.

    Geography filtering is intentionally NOT here. It is performed after
    merging current sources with state.json, so old and new nodes are treated
    exactly the same.
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
        }

        try:
            text = fetch(url)
        except Exception as e:
            print(f"WARNING: failed to load source {url}: {e}")
            continue

        if "://" not in text:
            try:
                decoded = b64decode(text).decode("utf-8", errors="replace")
                if "://" in decoded:
                    text = decoded
            except Exception:
                pass

        for line in text.splitlines():
            s = line.strip()

            if not s or s.startswith("#") or "://" not in s:
                continue

            s = clean_insecure_params(s)
            scheme = s.split("://", 1)[0].lower()

            if scheme not in SUPPORTED:
                continue

            k = canonical(s)

            if k in unique:
                duplicates += 1
                continue

            host = extract_server_host(s)
            if not host:
                source_parse_stats[url]["malformed"] += 1
                continue

            source_parse_stats[url]["parsed"] += 1
            source_stats[url] += 1
            unique[k] = s

    print(json.dumps({"source_parse_stats": source_parse_stats},
                     ensure_ascii=False, indent=2))

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
    security = q1(q, "security", "none")
    network = q1(q, "type", "tcp")
    st = {"network": network, "security": security}

    if security == "tls":
        tls = {"serverName": q1(q, "sni", "")}
        fp = q1(q, "fp", "")
        if fp:
            tls["fingerprint"] = fp
        if q1(q, "allowInsecure", q1(q, "insecure", "0")).lower() in {"1", "true"}:
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
        st["grpcSettings"] = {"serviceName": q1(q, "serviceName", q1(q, "service_name", ""))}
    elif network == "httpupgrade":
        st["httpupgradeSettings"] = {
            "path": unquote(q1(q, "path", "/")),
            "host": q1(q, "host", ""),
        }
    elif network == "xhttp":
        st["xhttpSettings"] = {
            "path": unquote(q1(q, "path", "/")),
            "host": q1(q, "host", ""),
            "mode": q1(q, "mode", "auto"),
        }
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
                    "id": p.username or "",
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
                "password": unquote(p.username or ""),
            }]},
            "streamSettings": stream_settings(q),
        }

    if scheme == "vmess":
        raw = uri[len("vmess://"):].split("#", 1)[0]
        o = json.loads(b64decode(raw).decode("utf-8", errors="replace"))
        fake_q = {
            "type": [o.get("net", "tcp")],
            "security": [o.get("tls", "") or "none"],
            "sni": [o.get("sni", "")],
            "host": [o.get("host", "")],
            "path": [o.get("path", "")],
            "fp": [o.get("fp", "")],
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
        raw = uri[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
        if "@" in raw:
            cred, addr = raw.rsplit("@", 1)
            cred_s = b64decode(cred).decode(errors="replace") if ":" not in cred else unquote(cred)
        else:
            decoded = b64decode(raw).decode(errors="replace")
            cred_s, addr = decoded.rsplit("@", 1)
        method, password = cred_s.split(":", 1)
        ap = urlsplit("ss://" + addr)
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": ap.hostname,
                "port": ap.port,
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

    outbound = {
        "type": "hysteria2",
        "tag": "probe-out",
        "server": p.hostname,
        "server_port": p.port,
        "password": unquote(p.username or ""),
        "tls": {
            "enabled": True,
            "server_name": q1(q, "sni", p.hostname or ""),
            "insecure": q1(q, "insecure", q1(q, "allowInsecure", "0")).lower() in {"1", "true"},
        },
    }
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


async def curl_url_probe(port: int, name: str, url: str, ok_codes):
    proc = await asyncio.create_subprocess_exec(
        "curl", "-fsS",
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

    if total_seconds > QUALITY_MAX_SECONDS:
        return Probe(
            False,
            error=f"{name}: too slow ({total_seconds:.2f}s)",
        )

    return Probe(
        True,
        latency_ms=round(total_seconds * 1000, 1),
    )


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
        result = await curl_url_probe(port, name, url, ok_codes)
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


async def main():
    OUT_DIR.mkdir(exist_ok=True)
    STATE_FILE.parent.mkdir(exist_ok=True)

    global CHEAP_PROBE_SEMAPHORE
    global VPN_PROCESS_SEMAPHORE

    CHEAP_PROBE_SEMAPHORE = asyncio.Semaphore(CHECK_CONCURRENCY)
    VPN_PROCESS_SEMAPHORE = asyncio.Semaphore(VPN_PROCESS_CONCURRENCY)

    source_nodes, source_stats, duplicates = collect_sources()
    old = load_state()
    now = int(time.time())

    # state.json is only a storage of previous candidates.
    # There are no trusted/old nodes. Every node (old or new) is checked from zero.
    candidates = dict(source_nodes)

    for key, item in old.items():
        uri = item.get("uri") if isinstance(item, dict) else None
        if not uri:
            continue
        candidates.setdefault(key, uri)

    # Remove duplicates again after merging old and new pools.
    merged = {}
    for uri in candidates.values():
        key = canonical(clean_insecure_params(uri))
        merged.setdefault(key, uri)

    # Geography is checked after complete deduplication and merging.
    # Unknown country and Russian IPs are rejected immediately.
    ru_networks = load_ru_networks()
    geo_passed_nodes = {}

    for key, uri in merged.items():
        host = extract_server_host(uri)
        if not host:
            continue

        country_check = is_russian_host(host, ru_networks)

        if country_check is not False:
            continue

        geo_passed_nodes[key] = uri

    current = {
        key: {
            "uri": uri,
            "last_latency_ms": None,
            "last_error": None,
        }
        for key, uri in geo_passed_nodes.items()
    }

    probe_stats = {
        name: {"checked": 0, "passed": 0, "failed": 0}
        for name in (
            "max",
            "chatgpt",
            "chatgpt_auth_tls",
            "chatgpt_android_tls",
            "youtube_204",
            "telegram_https",
            "telegram_mtproto",
        )
    }

    keys = list(current.keys())
    results = await asyncio.gather(
        *(safe_probe(current[k]["uri"], probe_stats) for k in keys)
    )

    deleted = 0
    successes = 0
    failures = 0

    for key, result in zip(keys, results):
        if key not in current:
            continue
        if result.ok:
            successes += 1
            current[key]["last_latency_ms"] = result.latency_ms
            current[key]["last_error"] = None
        else:
            failures += 1
            del current[key]
            deleted += 1

    # No internal ranking. Mihomo Meta / HiDefy perform AUTO selection.
    # Keep latency only as information in state/status.
    ordered = list(current.values())

    (OUT_DIR / "subscription.txt").write_text(
        "\n".join(x["uri"] for x in ordered) + ("\n" if ordered else ""),
        encoding="utf-8",
    )

    mihomo_nodes, mihomo_skipped = write_mihomo_files(ordered)

    STATE_FILE.write_text(
        json.dumps({"updated_at": now, "nodes": current}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    status = {
        "updated_at": now,
        "source_nodes_unique": len(source_nodes),
        "source_duplicates_removed": duplicates,
        "merged_candidates_after_dedup": len(merged),
        "checked_this_run": len(keys),
        "successful_this_run": successes,
        "failed_this_run": failures,
        "rejected_this_run": deleted,
        "published_nodes": len(current),
        "mihomo_nodes": mihomo_nodes,
        "mihomo_skipped": mihomo_skipped,
        "probe_stats": probe_stats,
        "admission_rule": "Only nodes that pass geography and all mandatory service probes are published. Any failed check removes the node immediately.",
        "note": "Node age does not matter. Previous nodes and new nodes are treated equally on every run.",
    }

    (OUT_DIR / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
