"""CTTO Module - HTTP Basic Authentication Honeypot.

Runs a Flask server protected by HTTP Basic auth. Every attempt is captured
from the auth callback, fingerprinted, logged, stored, and always rejected.
"""

import json
import threading

from flask import Flask, Response, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.serving import make_server

from core.module_loader import BaseModule
from modules.fingerprinting.request_fingerprint import (
    detect_attack_tool,
    detect_automation,
    detect_browser,
)


def _build_app(module: "BasicAuthModule") -> Flask:
    app = Flask(__name__)
    auth = HTTPBasicAuth()

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

    @auth.verify_password
    def verify_password(username, password):
        ip = _client_ip()
        user_agent = request.headers.get("User-Agent", "")
        headers = _serialise_headers()

        module.log_attack(
            ip=ip,
            username=username or "",
            password=password or "",
            method="BasicAuth",
            user_agent=user_agent,
            headers=headers,
        )
        module.log(f"Captured HTTP Basic attempt from {ip} for user={username!r}")
        return False

    @auth.error_handler
    def unauthorized(_status):
        return Response(
            "Invalid credentials",
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="CTTO Secure Area"'},
        )

    @app.get("/")
    @auth.login_required
    def index():
        return "ok"

    return app


class BasicAuthModule(BaseModule):
    name = "HTTP Basic Auth Honeypot"
    description = "Flask HTTP Basic honeypot that logs and stores all attempts"
    author = "CTTO Team"
    category = "auth"

    def run(self, host="0.0.0.0", port=8082, **kwargs):
        app = _build_app(self)
        self.log(f"Starting HTTP Basic honeypot on http://{host}:{port}")

        try:
            server = make_server(host, port, app)
        except (OSError, SystemExit) as exc:
            raise RuntimeError(f"Failed to bind {host}:{port}: {exc}") from exc

        self.engine.register_service("basic_auth", server)

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="BasicAuthHoneypot",
        )
        thread.start()

        self.log(f"HTTP Basic honeypot listening on {host}:{port} (Ctrl+C to stop)")
        try:
            thread.join()
        except KeyboardInterrupt:
            self.log("HTTP Basic honeypot stopped.")

        return f"HTTP Basic honeypot listening on port {port}"
