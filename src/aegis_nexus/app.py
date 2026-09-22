from __future__ import annotations

import hmac
import ipaddress
import json
import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from .model import EventValidationError, normalize_event
from .store import Store
from .study import explain
from .suricata import SuricataValidationError, normalize_eve_event


def _load_sensor_keys(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    result: dict[str, str] = {}
    for sensor, key in list(parsed.items())[:128]:
        if isinstance(sensor, str) and isinstance(key, str) and sensor and key:
            result[sensor[:96]] = key[:512]
    return result


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=int(os.getenv("AEGIS_MAX_EVENT_BYTES", "65536")),
        DATABASE_PATH=os.getenv("AEGIS_DATABASE_PATH", "./data/aegis.db"),
        INGEST_API_KEY=os.getenv("AEGIS_INGEST_API_KEY", ""),
        SENSOR_KEYS=_load_sensor_keys(os.getenv("AEGIS_SENSOR_KEYS", "")),
        RETENTION_DAYS=int(os.getenv("AEGIS_RETENTION_DAYS", "30")),
    )
    if test_config:
        app.config.update(test_config)
    store = Store(app.config["DATABASE_PATH"])
    app.extensions["aegis_store"] = store
    store.prune(int(app.config.get("RETENTION_DAYS", 30)))

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    def authorized(sensor_id: str) -> bool:
        supplied_key = request.headers.get("X-Aegis-Key", "")
        supplied_sensor = request.headers.get("X-Aegis-Sensor", "")
        if supplied_sensor and supplied_sensor != sensor_id:
            return False
        sensor_keys = app.config.get("SENSOR_KEYS") or {}
        if sensor_keys:
            expected = sensor_keys.get(sensor_id)
            return bool(expected) and hmac.compare_digest(expected, supplied_key)
        expected = app.config.get("INGEST_API_KEY", "")
        return bool(expected) and hmac.compare_digest(expected, supplied_key)

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_exc):
        return jsonify({"error": "payload_too_large"}), 413

    @app.errorhandler(BadRequest)
    def bad_request(_exc):
        return jsonify({"error": "invalid_json"}), 400

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/api/v1/events")
    def ingest_event():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            payload = request.get_json()
            event = normalize_event(payload)
            if not authorized(event["honeypot"]):
                return jsonify({"error": "unauthorized"}), 401
            stored = store.ingest(event)
        except EventValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except Exception:
            app.logger.exception("event ingestion failed")
            return jsonify({"error": "ingestion_failed"}), 500
        return jsonify({"id": stored["id"], "session_id": stored["session_id"]}), 201

    @app.post("/api/v1/integrations/suricata/eve")
    def ingest_suricata():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        sensor_id = (request.headers.get("X-Aegis-Sensor") or "suricata-01")[:96]
        if not authorized(sensor_id):
            return jsonify({"error": "unauthorized"}), 401
        try:
            event = normalize_event(normalize_eve_event(request.get_json(), sensor_id))
            stored = store.ingest(event)
        except (SuricataValidationError, EventValidationError) as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except Exception:
            app.logger.exception("suricata ingestion failed")
            return jsonify({"error": "ingestion_failed"}), 500
        return jsonify({"id": stored["id"], "session_id": stored["session_id"]}), 201

    @app.get("/api/v1/events")
    def events():
        limit = request.args.get("limit", 100, type=int)
        q = request.args.get("q", type=str)
        filters = {
            key: request.args.get(key, type=str)
            for key in ("country", "protocol", "service", "honeypot", "severity", "source_ip", "session_id", "event_type")
        }
        return jsonify({"items": store.list_events(limit=limit, q=q, filters=filters)})

    @app.get("/api/v1/events/<event_id>")
    def event_detail(event_id: str):
        item = store.get_event(event_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/sessions/<session_id>")
    def session_detail(session_id: str):
        item = store.get_session(session_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/ips/<ip>")
    def ip_detail(ip: str):
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({"error": "invalid_ip"}), 422
        return jsonify(store.ip_profile(normalized))

    @app.get("/api/v1/dashboard")
    def dashboard():
        hours = request.args.get("hours", 24, type=int)
        q = request.args.get("q", type=str)
        include_sim = request.args.get("include_simulation", "false").lower() in {"1", "true", "yes"}
        return jsonify(store.dashboard(hours=hours, include_simulation=include_sim, q=q))

    @app.get("/api/v1/reports/session/<session_id>")
    def session_report(session_id: str):
        item = store.report(session_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/relations")
    def relations():
        return jsonify(store.relations(request.args.get("session_id", "")[:128]))

    @app.get("/api/v1/study/<event_id>")
    def study(event_id: str):
        item = store.get_event(event_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        return jsonify(explain(item, request.args.get("lang", "it")))

    return app


app = create_app()
