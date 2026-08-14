from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    ]

RU_IPV4_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
RU_IPV6_URL = "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone"

SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
STATE_FILE = Path("data/state.json")
OUT_DIR = Path("output")
BIN_DIR = Path("bin")
XRAY = BIN_DIR / "xray"
SINGBOX = BIN_DIR / "sing-box"

CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "16"))
PROBE_TIMEOUT = float(os.getenv("PROBE_TIMEOUT_SECONDS", "9"))

CHATGPT_PROBE_URL = os.getenv(
    "CHATGPT_PROBE_URL",
    "https://chatgpt.com/robots.txt",
)

YOUTUBE_PROBE_URL = os.getenv(
    "YOUTUBE_PROBE_URL",
    "https://www.youtube.com/generate_204",
)

QUALITY_MAX_SECONDS = float(os.getenv("QUALITY_MAX_SECONDS", "5"))

QUALITY_PROBES = (
    ("hiddify", "http://captive.apple.com/hotspot-detect.html", {"200"}),
    ("chatgpt", CHATGPT_PROBE_URL, {"200"}),
    ("youtube", YOUTUBE_PROBE_URL, {"204"}),
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
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    if scheme == "vmess":
        return uri.split("#", 1)[0]
    try:
        p = urlsplit(uri)
        q = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((p.scheme.lower(), p.netloc, p.path, q, ""))
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

    except Exception as e:
        print(f"WARNING: failed to extract server host: {e}")
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

    except Exception as e:
        print(f"WARNING: failed to check country for {host}: {e}")
        return None


def collect_sources():
    ru_networks = load_ru_networks()
    unique = {}
    source_stats = {}
    duplicates = 0

    for url in SOURCES:
        count = 0
        text = fetch(url)

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
            if "neth.anonch.net" in s and "type=xhttp" in s:
                continue
                
            scheme = s.split("://", 1)[0].lower()
            if scheme not in SUPPORTED:
                continue
                
            host = extract_server_host(s)
            
            if host:
                country_check = is_russian_host(host, ru_networks)
                
                if country_check is True or country_check is None:
                    continue
            
            count += 1
            k = canonical(s)
            if k in unique:
                duplicates += 1
            else:
                unique[k] = s
        source_stats[url] = count

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


async def quality_probe(port: int):
    latencies = []

    for name, url, ok_codes in QUALITY_PROBES:
        result = await curl_url_probe(
            port,
            name,
            url,
            ok_codes,
        )

        if not result.ok:
            return result

        if result.latency_ms is not None:
            latencies.append(result.latency_ms)

    average_latency = (
        round(sum(latencies) / len(latencies), 1)
        if latencies
        else None
    )

    return Probe(
        True,
        latency_ms=average_latency,
    )


async def curl_probe(port: int):
    return await quality_probe(port)


async def run_probe(uri: str):
    scheme = uri.split("://", 1)[0].lower()
    port = free_port()
    engine = XRAY if scheme in {"vless", "vmess", "trojan", "ss"} else SINGBOX
    cfg = xray_config(uri, port) if engine == XRAY else singbox_config(uri, port)

    if not engine.exists():
        return Probe(False, error=f"missing engine: {engine}")

    with tempfile.TemporaryDirectory(prefix="vpnprobe-") as td:
        cfgpath = Path(td) / "config.json"
        cfgpath.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

        proc = await asyncio.create_subprocess_exec(
            str(engine), "run", "-c", str(cfgpath),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            if not await wait_port(port):
                err = ""
                if proc.returncode is not None:
                    err = (await proc.stderr.read()).decode(errors="replace")[-400:]
                return Probe(False, error=err or "local SOCKS did not start")
            return await curl_probe(port)
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()


async def safe_probe(uri: str, sem: asyncio.Semaphore):
    async with sem:
        try:
            return await run_probe(uri)
        except Exception as e:
            return Probe(False, error=f"{type(e).__name__}: {e}")


async def main():
    OUT_DIR.mkdir(exist_ok=True)
    STATE_FILE.parent.mkdir(exist_ok=True)

    source_nodes, source_stats, duplicates = collect_sources()
    old = load_state()
    now = int(time.time())

    # New keys must pass a real VPN probe before they are published.
    # Previously proven keys may survive temporary failures and are removed
    # only after FAILURES_BEFORE_DELETE consecutive failed probes.
    current = {}
    for key, uri in source_nodes.items():
        previous = old.get(key, {})
        established = bool(previous.get("established", previous.get("last_ok") is not None))
        current[key] = {
            "uri": uri,
            "established": established,
            "failures": int(previous.get("failures", 0)) if established else 0,
            "last_ok": previous.get("last_ok") if established else None,
            "last_latency_ms": previous.get("last_latency_ms") if established else None,
            "last_error": previous.get("last_error") if established else None,
        }

    sem = asyncio.Semaphore(CHECK_CONCURRENCY)
    keys = list(current.keys())
    results = await asyncio.gather(*(safe_probe(current[k]["uri"], sem) for k in keys))

    deleted = 0
    successes = 0
    failures = 0
    rejected_new = 0
    newly_established = 0

    for key, result in zip(keys, results):
        item = current.get(key)
        if item is None:
            continue
        if result.ok:
            successes += 1
            if not item["established"]:
                newly_established += 1
            item["established"] = True
            item["failures"] = 0
            item["last_ok"] = now
            item["last_latency_ms"] = result.latency_ms
            item["last_error"] = None
        else:
            failures += 1
            item["last_latency_ms"] = None
            item["last_error"] = result.error

            if not item["established"]:
                rejected_new += 1

            del current[key]
            deleted += 1

    # Fastest successful nodes first; nodes with recent failure go below them.
    ordered = sorted(
        current.values(),
        key=lambda x: (
            x["failures"] != 0,
            x["last_latency_ms"] is None,
            x["last_latency_ms"] if x["last_latency_ms"] is not None else 10**12,
        ),
    )

    (OUT_DIR / "subscription.txt").write_text(
        "\n".join(x["uri"] for x in ordered) + ("\n" if ordered else ""),
        encoding="utf-8",
    )

    state = {
        "updated_at": now,
        "nodes": current,
    }
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    status = {
        "updated_at": now,
        "source_nodes_unique": len(source_nodes),
        "source_duplicates_removed": duplicates,
        "source_stats": source_stats,
        "checked_this_run": len(keys),
        "successful_this_run": successes,
        "failed_this_run": failures,
        "newly_established_this_run": newly_established,
        "rejected_new_this_run": rejected_new,
        "rejected_this_run": deleted,
        "published_nodes": len(current),
        "admission_rule": "A key is published only if it passes all probes in the current run.",
        "server_check_period_minutes": 5,
        "note": "Final per-device AUTO/failover is intentionally delegated to the VPN client.",
    }
    (OUT_DIR / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
