#!/usr/bin/env python3
"""Health-check: spin up each serve target, hit its endpoint, and verify.

Usage:
    python3 scripts/healthcheck.py                   # all 4 targets
    python3 scripts/healthcheck.py web-login api-auth # specific targets only

Requires: requests  (pip install requests)
"""

import os
import signal
import subprocess
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

BASE_DIR = str(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CTTO = os.path.join(BASE_DIR, "ctto.py")
PYTHON = sys.executable

# Each entry: (name, serve-arg, port, request-builder, expected-status)
TARGETS = {
    "web-login": {
        "port": 18091,
        "request": lambda p: requests.post(
            f"http://127.0.0.1:{p}/login",
            data={"username": "hc_web", "password": "hc_pw"},
            timeout=5,
        ),
        "expect": 401,
    },
    "api-auth": {
        "port": 18092,
        "request": lambda p: requests.post(
            f"http://127.0.0.1:{p}/api/v1/login",
            json={"username": "hc_api", "password": "hc_pw"},
            timeout=5,
        ),
        "expect": 401,
    },
    "basic-auth": {
        "port": 18093,
        "request": lambda p: requests.get(
            f"http://127.0.0.1:{p}/",
            auth=("hc_basic", "hc_pw"),
            timeout=5,
        ),
        "expect": 401,
    },
    "dashboard": {
        "port": 18094,
        "request": lambda p: requests.get(
            f"http://127.0.0.1:{p}/api/stats",
            headers={"X-CTTO-Admin-Key": "healthcheck"},
            timeout=5,
        ),
        "expect": 200,
    },
}

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def check(name: str, cfg: dict) -> bool:
    port = cfg["port"]
    env = os.environ.copy()
    if name == "dashboard":
        env["CTTO_DASHBOARD_KEY"] = "healthcheck"

    proc = subprocess.Popen(
        [PYTHON, CTTO, "serve", name, "--port", str(port)],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    try:
        time.sleep(2)
        resp = cfg["request"](port)
        ok = resp.status_code == cfg["expect"]
        status_text = f"{resp.status_code} (expected {cfg['expect']})"
        tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  [{tag}] {name:12s}  HTTP {status_text}")
        return ok
    except Exception as exc:
        print(f"  [{RED}FAIL{RESET}] {name:12s}  {exc}")
        return False
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> None:
    selected = sys.argv[1:] if len(sys.argv) > 1 else list(TARGETS)
    invalid = [t for t in selected if t not in TARGETS]
    if invalid:
        sys.exit(f"Unknown target(s): {', '.join(invalid)}.  Valid: {', '.join(TARGETS)}")

    print(f"CTTO Health Check — {len(selected)} target(s)\n")
    results = {}
    for name in selected:
        results[name] = check(name, TARGETS[name])

    passed = sum(results.values())
    total = len(results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
