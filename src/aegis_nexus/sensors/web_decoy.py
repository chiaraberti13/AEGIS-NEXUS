from __future__ import annotations

import os
import re

from flask import Flask, jsonify, request

from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("AEGIS_WEB_MAX_BODY", "16384"))
sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "web-decoy-01"))

SQLI = re.compile(r"(?:\bunion\b.+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=|--|/\*)", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c))", re.I)
SHELLISH = re.compile(r"(?:;|\|\||&&|\$\()(?:\s*)(?:curl|wget|bash|sh|powershell|cmd)\b", re.I)


def _remote_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _base_observed(audit: dict | None = None) -> dict:
    return {
        "source_ip": _remote_ip(),
        "service": "http",
        "protocol": "tcp",
        "destination_port": int(os.getenv("AEGIS_WEB_PORT", "8080")),
        "method": request.method,
        "path": bounded_text(request.path, 512, "observed.path", audit),
        "user_agent": bounded_text(
            request.headers.get("User-Agent") or "",
            1024,
            "observed.user_agent",
            audit,
        ),
    }


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
    return """<!doctype html><html><head><meta charset="utf-8"><title>Meridian Portal</title></head>
<body><h1>Meridian Logistics — Staff Portal</h1><form method="post" action="/login">
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
