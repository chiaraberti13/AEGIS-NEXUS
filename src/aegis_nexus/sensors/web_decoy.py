from __future__ import annotations

import os
from html import escape
import re

from flask import Flask, jsonify, request

from .base import SensorCapabilities, SensorConfig
from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient
from .registry import register_sensor
from .persona import load_persona
from ..network_evidence import make_network_evidence

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("AEGIS_WEB_MAX_BODY", "16384"))
sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "web-decoy-01"))
PERSONA = load_persona()

SQLI = re.compile(r"(?:\bunion\b.+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=|--|/\*)", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c))", re.I)
SHELLISH = re.compile(r"(?:;|\|\||&&|\$\()(?:\s*)(?:curl|wget|bash|sh|powershell|cmd)\b", re.I)


def _remote_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _remote_port() -> int | None:
    value = request.environ.get("REMOTE_PORT")
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _http_evidence(audit: dict | None = None) -> dict:
    selected_headers = {}
    for name in (
        "Host",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Content-Type",
        "Content-Length",
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Real-IP",
    ):
        value = request.headers.get(name)
        if value not in (None, ""):
            key = name.lower().replace("-", "_")
            selected_headers[key] = bounded_text(
                value,
                1024,
                f"observed.network.http.headers.{key}",
                audit,
            )
    http = {
        "method": request.method,
        "path": bounded_text(request.path, 512, "observed.network.http.path", audit),
        "request_version": bounded_text(
            request.environ.get("SERVER_PROTOCOL") or "",
            32,
            "observed.network.http.request_version",
            audit,
        ),
        "user_agent": bounded_text(
            request.headers.get("User-Agent") or "",
            1024,
            "observed.network.http.user_agent",
            audit,
        ),
        "headers": selected_headers,
    }
    if request.content_length is not None and request.content_length >= 0:
        http["content_length"] = int(request.content_length)
    return http


def _base_observed(audit: dict | None = None) -> dict:
    destination_port = int(os.getenv("AEGIS_WEB_PORT", "8080"))
    source_port = _remote_port()
    transport = {"protocol": "tcp", "destination_port": destination_port}
    observed = {
        "source_ip": _remote_ip(),
        "service": "http",
        "protocol": "tcp",
        "destination_port": destination_port,
        "method": request.method,
        "path": bounded_text(request.path, 512, "observed.path", audit),
        "user_agent": bounded_text(
            request.headers.get("User-Agent") or "",
            1024,
            "observed.user_agent",
            audit,
        ),
    }
    if source_port is not None:
        observed["source_port"] = source_port
        transport["source_port"] = source_port
    observed["network"] = make_network_evidence(
        "http_request",
        "application",
        transport=transport,
        http=_http_evidence(audit),
    )
    return observed


@app.after_request
def headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.errorhandler(404)
def not_found(_error):
    # Unknown paths are valuable scan evidence. Capture only bounded request metadata;
    # do not reflect attacker-controlled path content into an HTML response.
    audit: dict = {}
    observed = attach_capture_metadata(_base_observed(audit), audit)
    sensor.emit("web.request", observed, "low")
    return jsonify({"status": "not_found"}), 404


@app.get("/")
def index():
    audit: dict = {}
    observed = attach_capture_metadata(_base_observed(audit), audit)
    sensor.emit("web.request", observed)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{escape(PERSONA.web_title)}</title></head>
<body><h1>{escape(PERSONA.web_heading)}</h1><form method="post" action="/login">
<label>User <input name="username" maxlength="128"></label><label>Password <input type="password" name="password" maxlength="256"></label>
<button type="submit">Sign in</button></form></body></html>"""


@app.post("/login")
def login():
    audit: dict = {}
    raw_username = request.form.get("username") or ""
    raw_password = request.form.get("password") or ""
    username = bounded_text(raw_username, 128, "observed.credential.username", audit)
    password = bounded_text(
        raw_password,
        4096,
        "observed.credential.password",
        audit,
        fingerprint_original=True,
    )
    observed = _base_observed(audit)
    observed["credential"] = {"username": username, "password": password}
    attach_capture_metadata(observed, audit)
    combined = f"{raw_username} {raw_password}"
    derived = {}
    severity = "medium"
    if SQLI.search(combined):
        derived["ioc"] = [{"type": "pattern", "value": "sqli-like-input", "evidence": ["observed.credential"]}]
        severity = "high"
    sensor.emit("credential", observed, severity, derived)
    return jsonify({"status": "denied", "message": "Invalid credentials"}), 401


@app.route("/internal-db", methods=["GET", "POST"])
def internal_db():
    audit: dict = {}
    raw_query = request.values.get("q") or ""
    query = bounded_text(raw_query, 2048, "observed.payload", audit)
    observed = _base_observed(audit)
    observed["payload"] = query
    attach_capture_metadata(observed, audit)
    derived = {}
    severity = "low"
    if SQLI.search(raw_query):
        derived["ioc"] = [{"type": "pattern", "value": "sqli-like-input", "evidence": ["observed.payload"]}]
        severity = "high"
    if SHELLISH.search(raw_query):
        derived.setdefault("ioc", []).append({"type": "pattern", "value": "command-staging-like-input", "evidence": ["observed.payload"]})
        severity = "high"
    sensor.emit("web.payload", observed, severity, derived)
    return jsonify({"rows": [], "notice": "Archive database unavailable"})


@app.get("/viewer")
def viewer():
    audit: dict = {}
    raw_document = request.args.get("doc") or ""
    document = bounded_text(raw_document, 2048, "observed.payload", audit)
    observed = _base_observed(audit)
    observed["payload"] = document
    attach_capture_metadata(observed, audit)
    derived = {}
    severity = "low"
    if TRAVERSAL.search(raw_document):
        derived["ioc"] = [{"type": "pattern", "value": "path-traversal-like-input", "evidence": ["observed.payload"]}]
        severity = "high"
    sensor.emit("web.payload", observed, severity, derived)
    return jsonify({"document": "Document not available", "reference": document[:128]})


@register_sensor
class WebSensorPlugin:
    name = "web"
    capabilities = SensorCapabilities(
        protocols=("http", "tcp"),
        event_types=("web.request", "web.payload", "credential"),
        interaction_mode="emulated",
        network_evidence=("transport", "http"),
        captures_credentials=True,
        captures_payloads=True,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "web-decoy-01")[:96],
            enabled=os.getenv("AEGIS_WEB_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_WEB_BIND", "0.0.0.0"),
            ports={"http": int(os.getenv("AEGIS_WEB_PORT", "8080"))},
            options={
                "max_body": max(1024, min(int(os.getenv("AEGIS_WEB_MAX_BODY", "16384")), 1048576)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        global sensor
        sensor = SensorClient(config.sensor_id)
        heartbeat = sensor.start_heartbeat()
        app.config["MAX_CONTENT_LENGTH"] = int(config.options.get("max_body", 16384))
        try:
            app.run(host=config.bind_host, port=config.port("http"), threaded=True)
        finally:
            heartbeat.stop()


def main():
    WebSensorPlugin.run(WebSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
