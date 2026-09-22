from __future__ import annotations

import os
import re

from flask import Flask, jsonify, request

from .client import SensorClient

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("AEGIS_WEB_MAX_BODY", "16384"))
sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "web-decoy-01"))

SQLI = re.compile(r"(?:\bunion\b.+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=|--|/\*)", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c))", re.I)
SHELLISH = re.compile(r"(?:;|\|\||&&|\$\()(?:\s*)(?:curl|wget|bash|sh|powershell|cmd)\b", re.I)


def _remote_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _base_observed() -> dict:
    return {
        "source_ip": _remote_ip(),
        "service": "http",
        "protocol": "tcp",
        "destination_port": int(os.getenv("AEGIS_WEB_PORT", "8080")),
        "method": request.method,
        "path": request.path[:512],
        "user_agent": (request.headers.get("User-Agent") or "")[:1024],
    }


@app.after_request
def headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
def index():
    sensor.emit("web.request", _base_observed())
    return """<!doctype html><html><head><meta charset="utf-8"><title>Meridian Portal</title></head>
<body><h1>Meridian Logistics — Staff Portal</h1><form method="post" action="/login">
<label>User <input name="username" maxlength="128"></label><label>Password <input type="password" name="password" maxlength="256"></label>
<button type="submit">Sign in</button></form></body></html>"""


@app.post("/login")
def login():
    username = (request.form.get("username") or "")[:128]
    password = (request.form.get("password") or "")[:256]
    observed = _base_observed()
    observed["credential"] = {"username": username, "password": password}
    combined = f"{username} {password}"
    derived = {}
    severity = "medium"
    if SQLI.search(combined):
        derived["ioc"] = [{"type": "pattern", "value": "sqli-like-input", "evidence": ["observed.credential"]}]
        severity = "high"
    sensor.emit("credential", observed, severity, derived)
    return jsonify({"status": "denied", "message": "Invalid credentials"}), 401


@app.route("/internal-db", methods=["GET", "POST"])
def internal_db():
    query = (request.values.get("q") or "")[:2048]
    observed = _base_observed()
    observed["payload"] = query
    derived = {}
    severity = "low"
    if SQLI.search(query):
        derived["ioc"] = [{"type": "pattern", "value": "sqli-like-input", "evidence": ["observed.payload"]}]
        severity = "high"
    if SHELLISH.search(query):
        derived.setdefault("ioc", []).append({"type": "pattern", "value": "command-staging-like-input", "evidence": ["observed.payload"]})
        severity = "high"
    sensor.emit("web.payload", observed, severity, derived)
    return jsonify({"rows": [], "notice": "Archive database unavailable"})


@app.get("/viewer")
def viewer():
    document = (request.args.get("doc") or "")[:2048]
    observed = _base_observed()
    observed["payload"] = document
    derived = {}
    severity = "low"
    if TRAVERSAL.search(document):
        derived["ioc"] = [{"type": "pattern", "value": "path-traversal-like-input", "evidence": ["observed.payload"]}]
        severity = "high"
    sensor.emit("web.payload", observed, severity, derived)
    return jsonify({"document": "Document not available", "reference": document[:128]})
