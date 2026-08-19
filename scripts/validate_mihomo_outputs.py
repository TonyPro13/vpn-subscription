#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output"
MIHOMO = ROOT / "bin" / "mihomo"
PROVIDER_FILE = OUT_DIR / "mihomo-provider.yaml"
CONFIG_FILE = OUT_DIR / "mihomo.yaml"
STATUS_FILE = OUT_DIR / "status.json"


class ValidationError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_config_test(config_text: str, label: str) -> None:
    with tempfile.TemporaryDirectory(prefix="mihomo-test-") as td:
        workdir = Path(td)
        config_path = workdir / "config.yaml"
        config_path.write_text(config_text, encoding="utf-8")
        proc = subprocess.run(
            [str(MIHOMO), "-t", "-d", str(workdir), "-f", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=45,
        )
        if proc.returncode != 0:
            raise ValidationError(
                f"{label} failed Mihomo config validation:\n{proc.stdout[-6000:]}"
            )


def _standalone_provider_config(provider_text: str) -> str:
    return (
        'mixed-port: 17890\n'
        'mode: "rule"\n'
        f'{provider_text.rstrip()}\n'
        'rules:\n'
        '  - "MATCH,DIRECT"\n'
    )


def _replace_remote_provider_url(config_text: str, local_url: str) -> str:
    lines = config_text.splitlines()
    in_providers = False
    providers_indent = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if stripped == "proxy-providers:":
            in_providers = True
            providers_indent = indent
            continue

        if in_providers:
            if stripped and indent <= providers_indent:
                break
            if stripped.startswith("url:"):
                lines[index] = f'{" " * indent}url: {json.dumps(local_url)}'
                return "\n".join(lines) + "\n"

    raise ValidationError("Could not find proxy-provider URL in output/mihomo.yaml")


def _replace_mixed_port(config_text: str, port: int) -> str:
    lines = config_text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("mixed-port:"):
            indent = len(line) - len(line.lstrip(" "))
            lines[index] = f'{" " * indent}mixed-port: {port}'
            return "\n".join(lines) + "\n"
    raise ValidationError("Could not find mixed-port in output/mihomo.yaml")


def _inject_controller(config_text: str, port: int) -> str:
    return f'external-controller: "127.0.0.1:{port}"\n' + config_text


def _disable_provider_health_check_for_runtime(config_text: str) -> str:
    """
    Disable provider health-check only in the temporary runtime-validation copy.

    The published mihomo.yaml is left untouched and still checks nodes every
    60 seconds. Runtime validation only needs to prove provider loading and
    provider -> AUTO wiring; it must not launch a second CI reachability sweep.
    """
    lines = config_text.splitlines()
    in_proxy_providers = False
    providers_indent = None
    in_health_check = False
    health_indent = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if stripped == "proxy-providers:":
            in_proxy_providers = True
            providers_indent = indent
            continue

        if in_proxy_providers and stripped and indent <= providers_indent:
            break

        if in_proxy_providers and stripped == "health-check:":
            in_health_check = True
            health_indent = indent
            continue

        if in_health_check:
            if stripped and indent <= health_indent:
                in_health_check = False
                health_indent = None
                continue
            if stripped.startswith("enable:"):
                lines[index] = f'{" " * indent}enable: false'
                return "\n".join(lines) + "\n"

    raise ValidationError("Could not find provider health-check enable flag in output/mihomo.yaml")


def _wait_provider_nodes(
    controller_port: int,
    expected_nodes: int,
    proc: subprocess.Popen,
    timeout: float = 20.0,
):
    """
    Mihomo starts the REST API before HTTP providers are guaranteed to finish
    their initial asynchronous load. Poll until the freshly served provider is
    actually populated instead of treating the first empty API response as a
    failure.
    """
    deadline = time.monotonic() + timeout
    last_count = None
    last_error = None
    refresh_requested = False

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ValidationError(
                f"Mihomo exited while waiting for provider initialization "
                f"with code {proc.returncode}"
            )

        try:
            provider = _api_json(
                controller_port,
                "/providers/proxies/VPN",
                timeout=2.0,
            )
            provider_proxies = provider.get("proxies") or []
            provider_names = {
                str(item.get("name"))
                for item in provider_proxies
                if isinstance(item, dict) and item.get("name")
            }
            last_count = len(provider_names)

            if last_count == expected_nodes:
                return provider_names

            # If the provider object already exists but is still empty, request
            # one explicit refresh. Mihomo's provider update API is asynchronous,
            # so we keep polling afterwards.
            if not refresh_requested:
                try:
                    _api_request(
                        controller_port,
                        "/providers/proxies/VPN",
                        method="PUT",
                        timeout=2.0,
                    )
                    refresh_requested = True
                except Exception as exc:
                    last_error = exc

        except Exception as exc:
            last_error = exc

        time.sleep(0.2)

    detail = f"last_loaded={last_count}"
    if last_error is not None:
        detail += f", last_error={type(last_error).__name__}: {last_error}"
    raise ValidationError(
        "Timed out waiting for Mihomo to load the fresh VPN provider: "
        f"expected={expected_nodes}, {detail}"
    )


def _wait_auto_membership(
    controller_port: int,
    provider_names: set[str],
    proc: subprocess.Popen,
    timeout: float = 10.0,
):
    """
    Provider-backed proxy groups can become visible slightly after the provider
    itself is populated. Poll AUTO until it contains the provider nodes.
    """
    deadline = time.monotonic() + timeout
    last_missing = set(provider_names)
    last_error = None

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ValidationError(
                f"Mihomo exited while waiting for AUTO membership "
                f"with code {proc.returncode}"
            )

        try:
            auto = _api_json(controller_port, "/proxies/AUTO", timeout=2.0)
            auto_names = {str(name) for name in (auto.get("all") or [])}
            last_missing = provider_names - auto_names
            if not last_missing:
                return
        except Exception as exc:
            last_error = exc

        time.sleep(0.2)

    sample = ", ".join(sorted(last_missing)[:10])
    detail = f"missing={len(last_missing)}"
    if sample:
        detail += f", sample={sample}"
    if last_error is not None:
        detail += f", last_error={type(last_error).__name__}: {last_error}"
    raise ValidationError(
        "AUTO did not receive all VPN provider nodes via use: [VPN] "
        f"within the initialization window: {detail}"
    )


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass


def _api_json(controller_port: int, path: str, timeout: float = 3.0):
    url = f"http://127.0.0.1:{controller_port}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _api_request(controller_port: int, path: str, method: str = "GET", timeout: float = 3.0):
    url = f"http://127.0.0.1:{controller_port}{path}"
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status


def _wait_api(controller_port: int, proc: subprocess.Popen, timeout: float = 12.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ValidationError(f"Mihomo exited during runtime validation with code {proc.returncode}")
        try:
            return _api_json(controller_port, "/version", timeout=1.0)
        except Exception as exc:
            last_error = exc
            time.sleep(0.1)
    raise ValidationError(f"Mihomo API did not become ready: {last_error}")


def _runtime_provider_validation(config_text: str, expected_nodes: int) -> None:
    with tempfile.TemporaryDirectory(prefix="mihomo-runtime-") as td:
        workdir = Path(td)
        controller_port = _free_port()
        mixed_port = _free_port()

        handler = partial(_QuietHandler, directory=str(OUT_DIR))
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        http_port = httpd.server_address[1]
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()

        local_provider_url = f"http://127.0.0.1:{http_port}/{PROVIDER_FILE.name}"
        runtime_config = _replace_remote_provider_url(config_text, local_provider_url)
        runtime_config = _disable_provider_health_check_for_runtime(runtime_config)
        runtime_config = _replace_mixed_port(runtime_config, mixed_port)
        runtime_config = _inject_controller(runtime_config, controller_port)

        config_path = workdir / "config.yaml"
        config_path.write_text(runtime_config, encoding="utf-8")
        log_path = workdir / "mihomo.log"

        log_file = log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            [str(MIHOMO), "-d", str(workdir), "-f", str(config_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            _wait_api(controller_port, proc)

            provider_names = _wait_provider_nodes(
                controller_port,
                expected_nodes,
                proc,
                timeout=20.0,
            )

            _wait_auto_membership(
                controller_port,
                provider_names,
                proc,
                timeout=10.0,
            )
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            log_file.close()
            httpd.shutdown()
            httpd.server_close()

            if proc.returncode not in (0, -15):
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                raise ValidationError(
                    f"Mihomo runtime validation exited with code {proc.returncode}:\n"
                    f"{log_text[-6000:]}"
                )


def main() -> int:
    for path in (MIHOMO, PROVIDER_FILE, CONFIG_FILE, STATUS_FILE):
        if not path.exists():
            raise ValidationError(f"Required file is missing: {path}")

    provider_text = PROVIDER_FILE.read_text(encoding="utf-8")
    config_text = CONFIG_FILE.read_text(encoding="utf-8")
    status = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    expected_nodes = int(status.get("mihomo_nodes", -1))

    if expected_nodes <= 0:
        raise ValidationError(
            f"Refusing to publish an unusable Mihomo provider: mihomo_nodes={expected_nodes}"
        )

    # 1) Validate every generated proxy object as a real Mihomo configuration.
    _run_config_test(
        _standalone_provider_config(provider_text),
        "Generated mihomo-provider.yaml",
    )

    # 2) Validate the client config structure using the freshly generated provider,
    #    served locally so the test never sees the previous GitHub commit.
    local_test_port = _free_port()
    handler = partial(_QuietHandler, directory=str(OUT_DIR))
    httpd = ThreadingHTTPServer(("127.0.0.1", local_test_port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        local_url = f"http://127.0.0.1:{local_test_port}/{PROVIDER_FILE.name}"
        local_config = _replace_remote_provider_url(config_text, local_url)
        _run_config_test(local_config, "Generated mihomo.yaml + fresh local provider")
    finally:
        httpd.shutdown()
        httpd.server_close()

    # 3) Start the real Mihomo core and verify that the provider is loaded and that
    #    AUTO actually receives all nodes through `use: [VPN]`. Provider startup is
    #    asynchronous, so this step waits for initialization instead of checking the
    #    first API response. The temporary runtime copy disables health-check to avoid
    #    a second CI reachability sweep; the published config still health-checks every
    #    60 seconds on the user's Mihomo client.
    _runtime_provider_validation(config_text, expected_nodes)

    print(json.dumps({
        "mihomo_validation": "ok",
        "provider_nodes": expected_nodes,
        "provider_file": str(PROVIDER_FILE.relative_to(ROOT)),
        "config_file": str(CONFIG_FILE.relative_to(ROOT)),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"MIHOMO VALIDATION FAILED: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
