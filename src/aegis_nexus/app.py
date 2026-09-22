from __future__ import annotations

import atexit
import csv
import hmac
import io
import ipaddress
import json
import os
import sqlite3

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from .casework import CaseValidationError, normalize_case_create, normalize_case_update, normalize_evidence, normalize_note
from .derivation import derive_observed_artifacts
from .enrichment import LocalGeoIPEnricher
from .model import EventValidationError, normalize_event
from .security import SlidingWindowLimiter, verify_signed_payload
from .store import Store
from .study import explain, explain_session
from .suricata import SuricataValidationError, normalize_eve_event


FILTER_KEYS = ("country", "protocol", "service", "honeypot", "severity", "source_ip", "session_id", "event_type")


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


def _csv_safe(value):
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _filters_from_request() -> dict[str, str]:
    return {
        key: value[:256]
        for key in FILTER_KEYS
        if (value := request.args.get(key, type=str))
    }


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=int(os.getenv("AEGIS_MAX_EVENT_BYTES", "65536")),
        DATABASE_PATH=os.getenv("AEGIS_DATABASE_PATH", "./data/aegis.db"),
        INGEST_API_KEY=os.getenv("AEGIS_INGEST_API_KEY", ""),
        SENSOR_KEYS=_load_sensor_keys(os.getenv("AEGIS_SENSOR_KEYS", "")),
        RETENTION_DAYS=int(os.getenv("AEGIS_RETENTION_DAYS", "30")),
        MAX_DB_EVENTS=int(os.getenv("AEGIS_MAX_DB_EVENTS", "500000")),
        ANALYTICS_MAX_EVENTS=int(os.getenv("AEGIS_ANALYTICS_MAX_EVENTS", "20000")),
        OPERATOR_API_KEY=os.getenv("AEGIS_OPERATOR_API_KEY", ""),
        REQUIRE_SENSOR_SIGNATURE=os.getenv("AEGIS_REQUIRE_SENSOR_SIGNATURE", "false").lower() in {"1", "true", "yes"},
        SENSOR_SIGNATURE_MAX_SKEW=int(os.getenv("AEGIS_SENSOR_SIGNATURE_MAX_SKEW", "300")),
        INGEST_RATE_LIMIT=int(os.getenv("AEGIS_INGEST_RATE_LIMIT_PER_MINUTE", "600")),
        OPERATOR_RATE_LIMIT=int(os.getenv("AEGIS_OPERATOR_RATE_LIMIT_PER_MINUTE", "1200")),
        GEOIP_CITY_DB=os.getenv("AEGIS_GEOIP_CITY_DB", ""),
        GEOIP_ASN_DB=os.getenv("AEGIS_GEOIP_ASN_DB", ""),
    )
    if test_config:
        app.config.update(test_config)

    store = Store(
        app.config["DATABASE_PATH"],
        retention_days=int(app.config.get("RETENTION_DAYS", 30)),
        max_events=int(app.config.get("MAX_DB_EVENTS", 500000)),
        analytics_max_events=int(app.config.get("ANALYTICS_MAX_EVENTS", 20000)),
    )
    limiter = SlidingWindowLimiter()
    enricher = app.config.get("ENRICHER")
    if enricher is None:
        enricher = LocalGeoIPEnricher(
            str(app.config.get("GEOIP_CITY_DB") or ""),
            str(app.config.get("GEOIP_ASN_DB") or ""),
        )
    app.extensions["aegis_store"] = store
    app.extensions["aegis_rate_limiter"] = limiter
    app.extensions["aegis_enricher"] = enricher
    close_enricher = getattr(enricher, "close", None)
    if callable(close_enricher):
        atexit.register(close_enricher)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    def sensor_secret(sensor_id: str) -> str:
        sensor_keys = app.config.get("SENSOR_KEYS") or {}
        if sensor_keys:
            return str(sensor_keys.get(sensor_id) or "")
        return str(app.config.get("INGEST_API_KEY", ""))

    def sensor_authorized(sensor_id: str, raw_body: bytes) -> bool:
        supplied_key = request.headers.get("X-Aegis-Key", "")
        supplied_sensor = request.headers.get("X-Aegis-Sensor", "")
        if supplied_sensor and supplied_sensor != sensor_id:
            return False
        expected = sensor_secret(sensor_id)
        if not expected or not hmac.compare_digest(expected, supplied_key):
            return False
        if app.config.get("REQUIRE_SENSOR_SIGNATURE"):
            return verify_signed_payload(
                expected,
                request.headers.get("X-Aegis-Timestamp", ""),
                request.headers.get("X-Aegis-Signature", ""),
                raw_body,
                int(app.config.get("SENSOR_SIGNATURE_MAX_SKEW", 300)),
            )
        return True

    def operator_authorized() -> bool:
        expected = str(app.config.get("OPERATOR_API_KEY", ""))
        if not expected:
            return True
        supplied = request.headers.get("X-Aegis-Operator-Key", "")
        return bool(supplied) and hmac.compare_digest(expected, supplied)

    @app.before_request
    def protect_operator_api():
        if not request.path.startswith("/api/v1/"):
            return None
        if request.path == "/api/v1/operator/status":
            return None
        if request.method == "POST" and request.path in {"/api/v1/events", "/api/v1/integrations/suricata/eve"}:
            return None
        if not operator_authorized():
            return jsonify({"error": "operator_unauthorized"}), 401
        remote = request.remote_addr or "unknown"
        if not limiter.allow(
            f"operator:{remote}",
            int(app.config.get("OPERATOR_RATE_LIMIT", 1200)),
            60,
        ):
            return jsonify({"error": "rate_limited"}), 429
        return None

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

    @app.get("/api/v1/operator/status")
    def operator_status():
        remote = request.remote_addr or "unknown"
        if not limiter.allow(f"operator-status:{remote}", 60, 60):
            return jsonify({"error": "rate_limited"}), 429
        authenticated = operator_authorized()
        payload = {
            "required": bool(app.config.get("OPERATOR_API_KEY")),
            "authenticated": authenticated,
        }
        if authenticated:
            sensor_keys = app.config.get("SENSOR_KEYS") or {}
            payload["sensor_auth_mode"] = "per_sensor_allowlist" if sensor_keys else (
                "shared_key" if app.config.get("INGEST_API_KEY") else "unconfigured"
            )
            payload["sensor_allowlist_count"] = len(sensor_keys)
        return jsonify(payload)

    @app.post("/api/v1/events")
    def ingest_event():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            raw_body = request.get_data(cache=True)
            payload = request.get_json()
            sensor_id = str(payload.get("honeypot") or "")[:96] if isinstance(payload, dict) else ""
            if not sensor_authorized(sensor_id, raw_body):
                return jsonify({"error": "unauthorized"}), 401
            if not limiter.allow(
                f"ingest:{sensor_id}:{request.remote_addr or 'unknown'}",
                int(app.config.get("INGEST_RATE_LIMIT", 600)),
                60,
            ):
                return jsonify({"error": "rate_limited"}), 429
            event = normalize_event(payload)
            event = derive_observed_artifacts(event)
            event = enricher.enrich(event)
            stored = store.ingest(event)
        except sqlite3.IntegrityError:
            return jsonify({"error": "duplicate_event"}), 409
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
        try:
            raw_body = request.get_data(cache=True)
            if not sensor_authorized(sensor_id, raw_body):
                return jsonify({"error": "unauthorized"}), 401
            if not limiter.allow(
                f"suricata:{sensor_id}:{request.remote_addr or 'unknown'}",
                int(app.config.get("INGEST_RATE_LIMIT", 600)),
                60,
            ):
                return jsonify({"error": "rate_limited"}), 429
            event = normalize_event(normalize_eve_event(request.get_json(), sensor_id))
            event = derive_observed_artifacts(event)
            event = enricher.enrich(event)
            stored = store.ingest(event)
        except sqlite3.IntegrityError:
            return jsonify({"error": "duplicate_event"}), 409
        except (SuricataValidationError, EventValidationError) as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except Exception:
            app.logger.exception("suricata ingestion failed")
            return jsonify({"error": "ingestion_failed"}), 500
        return jsonify({"id": stored["id"], "session_id": stored["session_id"]}), 201

    @app.get("/api/v1/events")
    def events():
        return jsonify({
            "items": store.list_events(
                limit=request.args.get("limit", 100, type=int),
                q=request.args.get("q", type=str),
                filters=_filters_from_request(),
                hours=request.args.get("hours", type=int),
            )
        })

    @app.get("/api/v1/events/<event_id>")
    def event_detail(event_id: str):
        item = store.get_event(event_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/sessions")
    def sessions():
        return jsonify({
            "items": store.list_sessions(
                limit=request.args.get("limit", 100, type=int),
                q=request.args.get("q", type=str),
            )
        })

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

    @app.get("/api/v1/ips/<ip>/threat-intelligence")
    def ip_threat_intelligence(ip: str):
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({"error": "invalid_ip"}), 422
        return jsonify(store.threat_intelligence(normalized))

    @app.get("/api/v1/enrichment/status")
    def enrichment_status():
        status = getattr(enricher, "status", None)
        return jsonify(status() if callable(status) else {
            "mode": "custom",
            "configured": True,
            "network_requests": None,
        })

    @app.get("/api/v1/meta/filters")
    def filter_options():
        return jsonify(store.filter_options(request.args.get("hours", 720, type=int)))

    @app.get("/api/v1/dashboard")
    def dashboard():
        hours = request.args.get("hours", 24, type=int)
        q = request.args.get("q", type=str)
        include_sim = request.args.get("include_simulation", "false").lower() in {"1", "true", "yes"}
        return jsonify(
            store.dashboard(
                hours=hours,
                include_simulation=include_sim,
                q=q,
                filters=_filters_from_request(),
            )
        )

    @app.get("/api/v1/cases")
    def cases():
        return jsonify({
            "items": store.list_cases(
                limit=request.args.get("limit", 100, type=int),
                q=request.args.get("q", type=str),
                status=request.args.get("status", type=str),
            )
        })

    @app.post("/api/v1/cases")
    def create_case():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            item = store.create_case(normalize_case_create(request.get_json()))
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        return jsonify(item), 201

    @app.get("/api/v1/cases/<case_id>")
    def case_detail(case_id: str):
        item = store.get_case(case_id[:128])
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.patch("/api/v1/cases/<case_id>")
    def update_case(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            item = store.update_case(case_id[:128], normalize_case_update(request.get_json()))
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.post("/api/v1/cases/<case_id>/evidence")
    def add_case_evidence(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            evidence = normalize_evidence(request.get_json())
            item = store.add_case_evidence(case_id[:128], evidence["type"], evidence["id"])
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except ValueError as exc:
            if str(exc) == "evidence_not_found":
                return jsonify({"error": "evidence_not_found"}), 404
            if str(exc) == "case_evidence_limit":
                return jsonify({"error": "case_evidence_limit"}), 422
            raise
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.delete("/api/v1/cases/<case_id>/evidence/<int:evidence_row_id>")
    def remove_case_evidence(case_id: str, evidence_row_id: int):
        try:
            item = store.remove_case_evidence(case_id[:128], evidence_row_id)
        except ValueError as exc:
            if str(exc) == "evidence_not_found":
                return jsonify({"error": "evidence_not_found"}), 404
            raise
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.post("/api/v1/cases/<case_id>/notes")
    def add_case_note(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            item = store.add_case_note(case_id[:128], normalize_note(request.get_json()))
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except ValueError as exc:
            if str(exc) == "case_note_limit":
                return jsonify({"error": "case_note_limit"}), 422
            raise
        return (jsonify(item), 201) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/reports/case/<case_id>")
    def case_report(case_id: str):
        item = store.case_report(case_id[:128])
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/reports/case/<case_id>.csv")
    def case_report_csv(case_id: str):
        item = store.case_report(case_id[:128])
        if not item:
            return jsonify({"error": "not_found"}), 404
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "case_id",
            "case_title",
            "case_status",
            "case_severity",
            "classification_provenance",
            "evidence_type",
            "evidence_id",
            "evidence_available",
            "evidence_added_at",
        ])
        for evidence in item["evidence"]:
            writer.writerow([
                _csv_safe(item["case"]["id"]),
                _csv_safe(item["case"]["title"]),
                _csv_safe(item["case"]["status"]),
                _csv_safe(item["case"]["severity"]),
                "analyst",
                _csv_safe(evidence["evidence_type"]),
                _csv_safe(evidence["evidence_id"]),
                _csv_safe(evidence["available"]),
                _csv_safe(evidence["added_at"]),
            ])
        filename = f"aegis-{case_id[:64]}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/v1/reports/session/<session_id>")
    def session_report(session_id: str):
        item = store.report(session_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @app.get("/api/v1/reports/session/<session_id>.csv")
    def session_report_csv(session_id: str):
        item = store.report(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp",
            "event_id",
            "event_type",
            "severity",
            "source_ip",
            "honeypot",
            "service",
            "protocol",
            "destination_port",
            "username",
            "command",
            "payload",
            "ids_signature",
        ])
        for event in item["events"]:
            observed = event.get("observed") or {}
            credential = observed.get("credential") if isinstance(observed.get("credential"), dict) else {}
            alert = observed.get("alert") if isinstance(observed.get("alert"), dict) else {}
            writer.writerow([
                _csv_safe(event.get("timestamp")),
                _csv_safe(event.get("id")),
                _csv_safe(event.get("event_type")),
                _csv_safe(event.get("severity")),
                _csv_safe(event.get("source_ip")),
                _csv_safe(event.get("honeypot")),
                _csv_safe(event.get("service")),
                _csv_safe(event.get("protocol")),
                _csv_safe(event.get("destination_port")),
                _csv_safe(credential.get("username")),
                _csv_safe(observed.get("command")),
                _csv_safe(observed.get("payload")),
                _csv_safe(alert.get("signature")),
            ])
        filename = f"aegis-{session_id[:64]}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/v1/relations")
    def relations():
        return jsonify(store.relations(request.args.get("session_id", "")[:128]))

    @app.get("/api/v1/study/<event_id>")
    def study(event_id: str):
        item = store.get_event(event_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        return jsonify(explain(item, request.args.get("lang", "it")))

    @app.get("/api/v1/study/session/<session_id>")
    def study_session(session_id: str):
        item = store.get_session(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        return jsonify(explain_session(item, request.args.get("lang", "it")))

    return app


app = create_app()
