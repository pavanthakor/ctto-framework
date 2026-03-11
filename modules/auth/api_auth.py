"""CTTO Module — REST API Login Honeypot

Runs a Flask JSON API on port 8081 that mimics a real authentication endpoint.
Every POST to /api/v1/login is:
    • logged    via engine.logger.log_attack()
    • persisted via engine.db.log_attack(method="API/Login")

Always returns {"status": "invalid"} with HTTP 401.

Usage via CLI:
    python3 ctto.py analyze --module auth/api_auth

Or programmatically:
    engine.run_module("auth/api_auth")
"""

import json
import os
import threading

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from core.module_loader import BaseModule
from modules.fingerprinting.request_fingerprint import (
    detect_attack_tool,
    detect_automation,
    detect_browser,
)

_HOST = "0.0.0.0"
_PORT = 8081


def _make_api(logger, db) -> Flask:
    """Build and return the configured Flask API application."""
    app = Flask(__name__)
    app.secret_key = os.environ.get("CTTO_SECRET", os.urandom(32))

    def _client_ip() -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _serialise_headers() -> str:
        raw_headers = {k: v for k, v in request.headers if k.lower() != "cookie"}
        user_agent = raw_headers.get("User-Agent", "")
        browser = detect_browser(user_agent)
        automation = detect_automation(raw_headers)
        tool = detect_attack_tool(user_agent)
        payload = {
            "raw": raw_headers,
            "fingerprint": {
                "browser": browser,
                "automation": automation,
                "tool": tool,
            },
        }
        return json.dumps(payload)

    def _capture(ip, username, password, user_agent, headers):
        logger.log_attack(
            ip=ip,
            username=username,
            password=password,
            method="API/Login",
            user_agent=user_agent,
        )
        attempt_id = db.log_attack(
            ip=ip,
            username=username,
            password=password,
            method="API/Login",
            user_agent=user_agent,
            headers=headers,
        )
        logger.info(
            f"[APIAuth] Attempt #{attempt_id} captured  ip={ip}  user={username!r}"
        )

    @app.get("/")
    @app.get("/api/v1/login")
    def api_login_page():
        return '''<!DOCTYPE html>
<html><head><title>API Login</title>
<style>
  body { font-family: system-ui; background: #0f172a; color: #e2e8f0; display: flex;
         align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #1e293b; border-radius: 12px; padding: 2rem; width: 380px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
  h2 { margin: 0 0 1rem; color: #38bdf8; }
  label { display: block; margin-top: 0.8rem; font-size: 0.85rem; color: #94a3b8; }
  input { width: 100%; padding: 0.6rem; margin-top: 0.3rem; border: 1px solid #334155;
          border-radius: 6px; background: #0f172a; color: #e2e8f0; font-size: 0.95rem;
          box-sizing: border-box; }
  button { margin-top: 1.2rem; width: 100%; padding: 0.65rem; background: #2563eb;
           border: none; border-radius: 6px; color: #fff; font-size: 1rem;
           font-weight: 600; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  #result { margin-top: 1rem; padding: 0.6rem; border-radius: 6px; display: none;
            font-size: 0.9rem; }
  .err { background: #7f1d1d; color: #fca5a5; }
  .sub { color: #64748b; font-size: 0.75rem; text-align: center; margin-top: 1rem; }
</style></head><body>
<div class="card">
  <h2>API Authentication</h2>
  <label>Username</label>
  <input id="user" placeholder="Enter username" />
  <label>Password</label>
  <input id="pass" type="password" placeholder="Enter password" />
  <button onclick="doLogin()">Authenticate</button>
  <div id="result"></div>
  <p class="sub">POST /api/v1/login &bull; JSON endpoint</p>
</div>
<script>
async function doLogin() {
  const r = await fetch("/api/v1/login", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: document.getElementById("user").value,
                          password: document.getElementById("pass").value})
  });
  const d = await r.json();
  const el = document.getElementById("result");
  el.style.display = "block";
  el.className = "err";
  el.textContent = "Authentication failed: " + d.status;
}
</script></body></html>'''

    @app.post("/api/v1/login")
    def api_login():
        ip         = _client_ip()
        user_agent = request.headers.get("User-Agent", "")
        headers    = _serialise_headers()

        body = request.get_json(silent=True, force=True) or {}
        if not isinstance(body, dict):
            body = {}

        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()

        if not username and not password:
            logger.warning(
                f"[APIAuth] Probe with no credentials  ip={ip}  user_agent={user_agent!r}"
            )

        _capture(ip, username, password, user_agent, headers)
        return jsonify({"status": "invalid"}), 401

    return app


class APIAuthHoneypot(BaseModule):
    name        = "API Auth Honeypot"
    description = "REST API honeypot — POST /api/v1/login, always returns {\"status\":\"invalid\"}"
    author      = "CTTO Team"
    category    = "auth"

    def run(self, host: str = _HOST, port: int = _PORT, **kwargs):
        app = _make_api(self.engine.logger, self.engine.db)

        self.log(f"Starting API honeypot on http://{host}:{port}/api/v1/login")

        try:
            server = make_server(host, port, app)
        except (OSError, SystemExit) as exc:
            raise RuntimeError(f"Failed to bind {host}:{port}: {exc}") from exc

        # Register concrete server object in engine services for lifecycle control.
        self.engine.register_service("api_auth", server)

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="APIAuthHoneypot",
        )
        thread.start()

        self.log(f"API honeypot listening on http://{host}:{port}/api/v1/login  (press Ctrl+C to stop)")

        try:
            thread.join()
        except KeyboardInterrupt:
            self.log("API honeypot stopped.")

        return f"APIAuth honeypot listening on port {port}"
