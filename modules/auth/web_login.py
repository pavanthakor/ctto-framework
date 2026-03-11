"""CTTO Module — Web Login Honeypot

Runs a Flask login portal on port 8080 inside the CTTO module framework.
Every credential submission is:
    • logged   via engine.logger.log_attack()
    • persisted via engine.db.log_attack(method="Web/Login")

The endpoint always returns "Invalid credentials" regardless of input.

Usage via CLI:
    python3 ctto.py analyze --module auth/web_login

Or programmatically:
    engine.run_module("auth/web_login")
    # server keeps running until the process is stopped
"""

import json
import os
import threading

from flask import Flask, render_template, request
from werkzeug.serving import make_server

from core.module_loader import BaseModule
from modules.fingerprinting.request_fingerprint import (
    detect_attack_tool,
    detect_automation,
    detect_browser,
)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TEMPLATES_DIR = os.path.join(_PROJECT_ROOT, "templates")
_HOST = "0.0.0.0"
_PORT = 8080


def _make_app(logger, db) -> Flask:
    """Build and return the configured Flask application."""
    app = Flask(__name__, template_folder=_TEMPLATES_DIR)
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
            method="Honeypot/Login",
            user_agent=user_agent,
        )
        attempt_id = db.log_attack(
            ip=ip,
            username=username,
            password=password,
            method="Web/Login",
            user_agent=user_agent,
            headers=headers,
        )
        logger.info(
            f"[WebLogin] Attempt #{attempt_id} captured  ip={ip}  user={username!r}"
        )

    @app.get("/login")
    def login_form():
        return render_template("login.html", error=None)

    @app.post("/login")
    def login_submit():
        username   = request.form.get("username", "").strip()
        password   = request.form.get("password", "").strip()
        ip         = _client_ip()
        user_agent = request.headers.get("User-Agent", "")
        _capture(ip, username, password, user_agent, _serialise_headers())
        return render_template(
            "login.html", error="Invalid credentials. Please try again."
        ), 401

    @app.get("/")
    def root():
        from flask import redirect
        return redirect("/login")

    return app


class WebLoginHoneypot(BaseModule):
    name        = "Web Login Honeypot"
    description = "Runs a Flask login portal honeypot on port 8080"
    author      = "CTTO Team"
    category    = "auth"

    def run(self, host: str = _HOST, port: int = _PORT, **kwargs):
        app = _make_app(self.engine.logger, self.engine.db)

        self.log(f"Starting honeypot on http://{host}:{port}")

        try:
            server = make_server(host, port, app)
        except (OSError, SystemExit) as exc:
            raise RuntimeError(f"Failed to bind {host}:{port}: {exc}") from exc

        # Register concrete server object in engine services for lifecycle control.
        self.engine.register_service("web_login", server)

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="WebLoginHoneypot",
        )
        thread.start()

        self.log(f"Honeypot listening on http://{host}:{port}/login  (press Ctrl+C to stop)")

        try:
            thread.join()
        except KeyboardInterrupt:
            self.log("Honeypot stopped.")

        return f"WebLogin honeypot listening on port {port}"
