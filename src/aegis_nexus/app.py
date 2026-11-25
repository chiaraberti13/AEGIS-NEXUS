from __future__ import annotations

import atexit
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import sqlite3
from pathlib import Path

from flask import Flask, Response, g, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from .alerts import AlertStore
from .benign_scanners import BenignScannerContext
from .behavioral_analytics import BehavioralAnalytics
from .cti_stix import export_stix_bundle
from .cti_sharing import sanitize_shareable_indicators
from .custom_feed import load_custom_feed_adapter_config
from .correlation_workspace import CorrelationWorkspace
from .detection import DetectionEngine
from .detection_backtest import DetectionBacktester
from .detection_config import DetectionConfig
from .api_activity import make_activity_blueprint
from .api_alerts import make_alerts_blueprint
from .api_analytics import make_analytics_blueprint
from .api_cases import make_cases_blueprint
from .api_detection_mgmt import make_detection_management_blueprint
from .api_detections import make_detections_blueprint
from .api_iocs import make_iocs_blueprint
from .api_ips import make_ips_blueprint
from .api_pcap import make_pcap_blueprint
from .api_reports import make_reports_blueprint
from .api_status import make_status_blueprint
from .detection_suppression import DetectionSuppressionStore
from .derivation import derive_observed_artifacts
from .enrichment import LocalGeoIPEnricher
from .forwarding import build_forwarder
from .logging_config import configure_app_logging
from .ioc import IOCWorkspace
from .model import EventValidationError, normalize_event
from .operator_audit import OperatorAuditLog
from .pcap import DisabledPcapCaptureProvider, PcapEvidenceStore
from .quarantine import QuarantineError, QuarantineStore
from .metrics import CONTENT_TYPE as PROMETHEUS_CONTENT_TYPE
from .metrics import render_prometheus
from .security import SlidingWindowLimiter, verify_signed_payload
from .sensor_sequence import SensorSequenceError, validate_heartbeat_sequence
from .store import Store
from .suricata import SuricataValidationError, normalize_eve_event
from .threat_context import LocalThreatContextEnricher
from .threat_intelligence import validate_provider
from .time_integrity import EventClockError, utc_now_iso, validate_event_clock


FILTER_KEYS = ("country", "asn", "destination_port", "protocol", "service", "honeypot", "severity", "source_ip", "session_id", "event_type")


MAX_OVERLAPPING_KEYS = 4


def _load_sensor_keys(raw: str) -> dict[str, str | list[str]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AEGIS_SENSOR_KEYS must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("AEGIS_SENSOR_KEYS must be a JSON object")

    result: dict[str, str | list[str]] = {}
    for sensor, key in list(parsed.items())[:128]:
        if not isinstance(sensor, str) or not sensor or len(sensor) > 96:
            raise ValueError("invalid sensor id in AEGIS_SENSOR_KEYS")
        if key in (None, ""):
            continue
        if isinstance(key, list):
            # Overlapping keys for zero-downtime rotation: the first entry is the
            # current key, the others are still accepted until the rotation ends.
            if len(key) > MAX_OVERLAPPING_KEYS or not all(isinstance(item, str) for item in key):
                raise ValueError(f"invalid secret list for sensor {sensor}")
            keys = [item[:512] for item in key if item]
            if keys:
                result[sensor] = keys
            continue
        if not isinstance(key, str):
            raise ValueError(f"invalid secret for sensor {sensor}")
        result[sensor] = key[:512]
    return result


def _secret_candidates(value) -> tuple[str, ...]:
    """Normalize a configured secret (string or list) to the accepted keys."""
    if not value:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value if item)[:MAX_OVERLAPPING_KEYS]


OPERATOR_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
MAX_OPERATOR_IDENTITIES = 64


def _load_operator_keys(raw: str) -> dict[str, str | list[str]]:
    """Parse per-analyst operator keys from a JSON object (name -> key or key list).

    Keeps the single-key lab mode intact: an empty value yields no named
    identities and callers fall back to ``AEGIS_OPERATOR_API_KEY``. Every
    captured value is treated as hostile, so the identity name charset, the
    identity count and each secret are bounded here rather than at use time.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AEGIS_OPERATOR_KEYS must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("AEGIS_OPERATOR_KEYS must be a JSON object")
    if len(parsed) > MAX_OPERATOR_IDENTITIES:
        raise ValueError(f"AEGIS_OPERATOR_KEYS supports at most {MAX_OPERATOR_IDENTITIES} identities")

    result: dict[str, str | list[str]] = {}
    for name, key in parsed.items():
        if not isinstance(name, str) or not OPERATOR_IDENTITY_PATTERN.fullmatch(name):
            raise ValueError("invalid operator identity in AEGIS_OPERATOR_KEYS")
        if key in (None, ""):
            continue
        if isinstance(key, list):
            # Overlapping keys for zero-downtime per-analyst key rotation: the
            # first entry is the current key, the others stay accepted until the
            # rotation ends.
            if len(key) > MAX_OVERLAPPING_KEYS or not all(isinstance(item, str) for item in key):
                raise ValueError(f"invalid secret list for operator {name}")
            keys = [item[:512] for item in key if item]
            if keys:
                result[name] = keys
            continue
        if not isinstance(key, str):
            raise ValueError(f"invalid secret for operator {name}")
        result[name] = key[:512]
    return result


def _load_sensor_source_cidrs(raw: str) -> dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AEGIS_SENSOR_SOURCE_CIDRS must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("AEGIS_SENSOR_SOURCE_CIDRS must be a JSON object")

    result: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    for sensor, cidr in list(parsed.items())[:128]:
        if not isinstance(sensor, str) or not sensor or len(sensor) > 96:
            raise ValueError("invalid sensor id in AEGIS_SENSOR_SOURCE_CIDRS")
        if not isinstance(cidr, str) or not cidr:
            raise ValueError(f"invalid source CIDR for sensor {sensor}")
        try:
            result[sensor] = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid source CIDR for sensor {sensor}") from exc
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


def _pagination_scope(resource: str, *, q: str | None = None, filters: dict[str, str] | None = None, hours: int | None = None) -> str:
    payload = {
        "resource": resource,
        "q": (q or "")[:128],
        "filters": {key: value for key, value in sorted((filters or {}).items()) if value},
        "hours": hours,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    event_max_bytes = int(os.getenv("AEGIS_MAX_EVENT_BYTES", "65536"))
    pcap_max_bytes = int(os.getenv("AEGIS_PCAP_MAX_BYTES", "1048576"))
    app.config.update(
        MAX_CONTENT_LENGTH=max(event_max_bytes, pcap_max_bytes + 131072),
        EVENT_MAX_BYTES=event_max_bytes,
        DATABASE_PATH=os.getenv("AEGIS_DATABASE_PATH", "./data/aegis.db"),
        INGEST_API_KEY=os.getenv("AEGIS_INGEST_API_KEY", ""),
        INGEST_API_KEY_PREVIOUS=os.getenv("AEGIS_INGEST_API_KEY_PREVIOUS", ""),
        SENSOR_KEYS=_load_sensor_keys(os.getenv("AEGIS_SENSOR_KEYS", "")),
        SENSOR_SOURCE_CIDRS=_load_sensor_source_cidrs(os.getenv("AEGIS_SENSOR_SOURCE_CIDRS", "")),
        RETENTION_DAYS=int(os.getenv("AEGIS_RETENTION_DAYS", "30")),
        MAX_DB_EVENTS=int(os.getenv("AEGIS_MAX_DB_EVENTS", "500000")),
        ANALYTICS_MAX_EVENTS=int(os.getenv("AEGIS_ANALYTICS_MAX_EVENTS", "20000")),
        SESSION_MAX_EVENTS=int(os.getenv("AEGIS_SESSION_MAX_EVENTS", "5000")),
        RELATION_MAX_NODES=int(os.getenv("AEGIS_RELATION_MAX_NODES", "160")),
        MAX_CASES=int(os.getenv("AEGIS_MAX_CASES", "10000")),
        CASE_RETENTION_DAYS=int(os.getenv("AEGIS_CASE_RETENTION_DAYS", "0")),
        MIN_FREE_BYTES=int(os.getenv("AEGIS_MIN_FREE_BYTES", "67108864")),
        BACKUP_DIR=os.getenv("AEGIS_BACKUP_DIR", "./data/backups"),
        BACKUP_KEEP=int(os.getenv("AEGIS_BACKUP_KEEP", "14")),
        OPERATOR_API_KEY=os.getenv("AEGIS_OPERATOR_API_KEY", ""),
        OPERATOR_API_KEY_PREVIOUS=os.getenv("AEGIS_OPERATOR_API_KEY_PREVIOUS", ""),
        OPERATOR_KEYS=_load_operator_keys(os.getenv("AEGIS_OPERATOR_KEYS", "")),
        OPERATOR_IDENTITY=(os.getenv("AEGIS_OPERATOR_IDENTITY", "").strip() or "operator"),
        ALLOW_UNAUTHENTICATED_OPERATOR=os.getenv("AEGIS_ALLOW_UNAUTHENTICATED_OPERATOR", "false").lower() in {"1", "true", "yes"},
        REQUIRE_SENSOR_SIGNATURE=os.getenv("AEGIS_REQUIRE_SENSOR_SIGNATURE", "false").lower() in {"1", "true", "yes"},
        SENSOR_SIGNATURE_MAX_SKEW=int(os.getenv("AEGIS_SENSOR_SIGNATURE_MAX_SKEW", "300")),
        SENSOR_REPLAY_MAX_NONCES_PER_SENSOR=int(os.getenv("AEGIS_SENSOR_REPLAY_MAX_NONCES_PER_SENSOR", "4096")),
        SENSOR_HEARTBEAT_STALE_SECONDS=int(os.getenv("AEGIS_SENSOR_HEARTBEAT_STALE_SECONDS", "180")),
        INGEST_RATE_LIMIT=int(os.getenv("AEGIS_INGEST_RATE_LIMIT_PER_MINUTE", "600")),
        OPERATOR_RATE_LIMIT=int(os.getenv("AEGIS_OPERATOR_RATE_LIMIT_PER_MINUTE", "1200")),
        GEOIP_CITY_DB=os.getenv("AEGIS_GEOIP_CITY_DB", ""),
        GEOIP_ASN_DB=os.getenv("AEGIS_GEOIP_ASN_DB", ""),
        THREAT_CONTEXT_FILE=os.getenv("AEGIS_THREAT_CONTEXT_FILE", ""),
        THREAT_CONTEXT_MAX_BYTES=int(os.getenv("AEGIS_THREAT_CONTEXT_MAX_BYTES", str(20 * 1024 * 1024))),
        THREAT_CONTEXT_MAX_INDICATORS=int(os.getenv("AEGIS_THREAT_CONTEXT_MAX_INDICATORS", "100000")),
        THREAT_CONTEXT_MAX_MATCHES=int(os.getenv("AEGIS_THREAT_CONTEXT_MAX_MATCHES", "32")),
        THREAT_CONTEXT_ADAPTER_JSON=os.getenv("AEGIS_THREAT_CONTEXT_ADAPTER_JSON", ""),
        THREAT_CONTEXT_ADAPTER_FILE=os.getenv("AEGIS_THREAT_CONTEXT_ADAPTER_FILE", ""),
        CTI_EXPORT_TLP=os.getenv("AEGIS_CTI_EXPORT_TLP", "TLP:AMBER+STRICT"),
        CTI_STALE_AFTER_DAYS=int(os.getenv("AEGIS_CTI_STALE_AFTER_DAYS", "30")),
        CTI_AGED_AFTER_DAYS=int(os.getenv("AEGIS_CTI_AGED_AFTER_DAYS", "90")),
        BENIGN_SCANNER_FILE=os.getenv("AEGIS_BENIGN_SCANNER_FILE", ""),
        BENIGN_SCANNER_MAX_BYTES=int(os.getenv("AEGIS_BENIGN_SCANNER_MAX_BYTES", "1048576")),
        BENIGN_SCANNER_MAX_ENTRIES=int(os.getenv("AEGIS_BENIGN_SCANNER_MAX_ENTRIES", "10000")),
        ANALYTICS_MIN_SAMPLES=int(os.getenv("AEGIS_ANALYTICS_MIN_SAMPLES", "20")),
        DETECTION_RULES_JSON=os.getenv("AEGIS_DETECTION_RULES_JSON", ""),
        MAX_FUTURE_EVENT_SKEW_SECONDS=int(os.getenv("AEGIS_MAX_FUTURE_EVENT_SKEW_SECONDS", "300")),
        PCAP_ENABLED=os.getenv("AEGIS_PCAP_ENABLED", "false").lower() in {"1", "true", "yes"},
        PCAP_DIR=os.getenv("AEGIS_PCAP_DIR", "/data/pcap"),
        PCAP_MAX_BYTES=pcap_max_bytes,
        PCAP_RETENTION_DAYS=int(os.getenv("AEGIS_PCAP_RETENTION_DAYS", "7")),
        PCAP_MAX_FILES=int(os.getenv("AEGIS_PCAP_MAX_FILES", "1000")),
        QUARANTINE_DIR=os.getenv("AEGIS_QUARANTINE_DIR", ""),
        QUARANTINE_MAX_BYTES=int(os.getenv("AEGIS_QUARANTINE_MAX_BYTES", "262144")),
        QUARANTINE_MAX_FILES=int(os.getenv("AEGIS_QUARANTINE_MAX_FILES", "1000")),
        AUDIT_LOG_RETENTION_DAYS=int(os.getenv("AEGIS_AUDIT_LOG_RETENTION_DAYS", "365")),
        AUDIT_LOG_MAX_ROWS=int(os.getenv("AEGIS_AUDIT_LOG_MAX_ROWS", "1000000")),
        FORWARDING_ENABLED=os.getenv("AEGIS_FORWARDING_ENABLED", "false").lower() in {"1", "true", "yes"},
        FORWARD_SYSLOG_HOST=os.getenv("AEGIS_FORWARD_SYSLOG_HOST", ""),
        FORWARD_SYSLOG_PORT=int(os.getenv("AEGIS_FORWARD_SYSLOG_PORT", "514")),
        FORWARD_SYSLOG_PROTOCOL=os.getenv("AEGIS_FORWARD_SYSLOG_PROTOCOL", "udp"),
        FORWARD_WEBHOOK_URL=os.getenv("AEGIS_FORWARD_WEBHOOK_URL", ""),
        FORWARD_WEBHOOK_SECRET=os.getenv("AEGIS_FORWARD_WEBHOOK_SECRET", ""),
        FORWARD_QUEUE_MAX=int(os.getenv("AEGIS_FORWARD_QUEUE_MAX", "1000")),
        FORWARD_MAX_RETRIES=int(os.getenv("AEGIS_FORWARD_MAX_RETRIES", "3")),
        LOG_FORMAT=os.getenv("AEGIS_LOG_FORMAT", "plain"),
    )
    if test_config:
        app.config.update(test_config)
    if str(app.config.get("LOG_FORMAT") or "").lower() == "json":
        configure_app_logging(app)
    app.config["MAX_CONTENT_LENGTH"] = max(
        int(app.config.get("MAX_CONTENT_LENGTH", 0)),
        int(app.config.get("EVENT_MAX_BYTES", 65536)),
        int(app.config.get("PCAP_MAX_BYTES", 1048576)) + 131072,
        int(app.config.get("QUARANTINE_MAX_BYTES", 262144)) + 4096,
    )

    store = Store(
        app.config["DATABASE_PATH"],
        retention_days=int(app.config.get("RETENTION_DAYS", 30)),
        max_events=int(app.config.get("MAX_DB_EVENTS", 500000)),
        analytics_max_events=int(app.config.get("ANALYTICS_MAX_EVENTS", 20000)),
        session_max_events=int(app.config.get("SESSION_MAX_EVENTS", 5000)),
        relation_max_nodes=int(app.config.get("RELATION_MAX_NODES", 160)),
        max_cases=int(app.config.get("MAX_CASES", 10000)),
        case_retention_days=int(app.config.get("CASE_RETENTION_DAYS", 0)),
        migration_backup_dir=str(app.config.get("BACKUP_DIR") or "./data/backups"),
        migration_backup_keep=int(app.config.get("BACKUP_KEEP", 14)),
    )
    alert_store = AlertStore(app.config["DATABASE_PATH"])
    ioc_workspace = IOCWorkspace(app.config["DATABASE_PATH"], max_events=int(app.config.get("ANALYTICS_MAX_EVENTS", 20000)))
    # Let cases resolve directly-linked IOC evidence without the Store importing
    # the IOC workspace (dependency injection keeps the layering clean).
    store.set_ioc_resolver(lambda ioc_identifier: ioc_workspace.get(ioc_identifier))
    correlation_workspace = CorrelationWorkspace(app.config["DATABASE_PATH"], max_events=int(app.config.get("ANALYTICS_MAX_EVENTS", 20000)))
    detection_config = DetectionConfig.from_json(str(app.config.get("DETECTION_RULES_JSON") or ""))
    detection_engine = DetectionEngine(config=detection_config)
    detection_suppressions = DetectionSuppressionStore(app.config["DATABASE_PATH"])
    detection_backtester = DetectionBacktester(detection_engine)
    pcap_store = PcapEvidenceStore(
        app.config["DATABASE_PATH"],
        str(app.config.get("PCAP_DIR") or "/data/pcap"),
        enabled=bool(app.config.get("PCAP_ENABLED")),
        max_bytes=int(app.config.get("PCAP_MAX_BYTES", 1048576)),
        retention_days=int(app.config.get("PCAP_RETENTION_DAYS", 7)),
        max_files=int(app.config.get("PCAP_MAX_FILES", 1000)),
    )
    quarantine_store = QuarantineStore(
        str(app.config.get("QUARANTINE_DIR") or os.path.join(os.path.dirname(os.path.abspath(app.config["DATABASE_PATH"])), "quarantine")),
        max_bytes=int(app.config.get("QUARANTINE_MAX_BYTES", 262144)),
        max_files=int(app.config.get("QUARANTINE_MAX_FILES", 1000)),
    )
    pcap_capture_provider = app.config.get("PCAP_CAPTURE_PROVIDER") or DisabledPcapCaptureProvider()
    audit_log = OperatorAuditLog(
        app.config["DATABASE_PATH"],
        retention_days=int(app.config.get("AUDIT_LOG_RETENTION_DAYS", 365)),
        max_rows=int(app.config.get("AUDIT_LOG_MAX_ROWS", 1_000_000)),
    )
    limiter = SlidingWindowLimiter()
    forwarder = app.config.get("FORWARDER") or build_forwarder(app.config, logger=app.logger)
    forwarder.start()
    enricher = app.config.get("ENRICHER")
    if enricher is None:
        enricher = LocalGeoIPEnricher(
            str(app.config.get("GEOIP_CITY_DB") or ""),
            str(app.config.get("GEOIP_ASN_DB") or ""),
        )
    threat_context = app.config.get("THREAT_CONTEXT")
    if threat_context is None:
        adapter_config = load_custom_feed_adapter_config(
            raw_json=str(app.config.get("THREAT_CONTEXT_ADAPTER_JSON") or ""),
            file_path=str(app.config.get("THREAT_CONTEXT_ADAPTER_FILE") or ""),
        )
        threat_context = LocalThreatContextEnricher(
            str(app.config.get("THREAT_CONTEXT_FILE") or ""),
            max_bytes=int(app.config.get("THREAT_CONTEXT_MAX_BYTES", 20 * 1024 * 1024)),
            max_indicators=int(app.config.get("THREAT_CONTEXT_MAX_INDICATORS", 100000)),
            max_matches=int(app.config.get("THREAT_CONTEXT_MAX_MATCHES", 32)),
            adapter_config=adapter_config,
            stale_after_days=int(app.config.get("CTI_STALE_AFTER_DAYS", 30)),
            aged_after_days=int(app.config.get("CTI_AGED_AFTER_DAYS", 90)),
        )
        validate_provider(threat_context)

    app.extensions["aegis_store"] = store
    app.extensions["aegis_alert_store"] = alert_store
    app.extensions["aegis_ioc_workspace"] = ioc_workspace
    app.extensions["aegis_correlation_workspace"] = correlation_workspace
    app.extensions["aegis_detection_engine"] = detection_engine
    app.extensions["aegis_detection_backtester"] = detection_backtester
    app.extensions["aegis_detection_suppressions"] = detection_suppressions
    app.extensions["aegis_pcap_store"] = pcap_store
    app.extensions["aegis_pcap_capture_provider"] = pcap_capture_provider
    app.extensions["aegis_quarantine_store"] = quarantine_store
    app.extensions["aegis_forwarder"] = forwarder
    app.extensions["aegis_audit_log"] = audit_log
    app.extensions["aegis_rate_limiter"] = limiter
    app.extensions["aegis_enricher"] = enricher
    app.extensions["aegis_threat_context"] = threat_context
    benign_scanners = BenignScannerContext(
        str(app.config.get("BENIGN_SCANNER_FILE") or ""),
        max_bytes=int(app.config.get("BENIGN_SCANNER_MAX_BYTES", 1048576)),
        max_entries=int(app.config.get("BENIGN_SCANNER_MAX_ENTRIES", 10000)),
    )

    app.extensions["aegis_threat_intelligence_provider"] = threat_context
    app.extensions["aegis_benign_scanners"] = benign_scanners
    behavioral_analytics = BehavioralAnalytics(
        min_samples=int(app.config.get("ANALYTICS_MIN_SAMPLES", 20)),
    )
    app.extensions["aegis_behavioral_analytics"] = behavioral_analytics
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

    def sensor_secrets(sensor_id: str) -> tuple[str, ...]:
        sensor_keys = app.config.get("SENSOR_KEYS") or {}
        if sensor_keys:
            return _secret_candidates(sensor_keys.get(sensor_id))
        return _secret_candidates([
            app.config.get("INGEST_API_KEY", ""),
            app.config.get("INGEST_API_KEY_PREVIOUS", ""),
        ])

    def remote_ip_address():
        try:
            remote = ipaddress.ip_address(request.remote_addr or "")
        except ValueError:
            return None
        if isinstance(remote, ipaddress.IPv6Address) and remote.ipv4_mapped is not None:
            return remote.ipv4_mapped
        return remote

    def sensor_source_allowed(sensor_id: str) -> bool:
        source_cidrs = app.config.get("SENSOR_SOURCE_CIDRS") or {}
        network = source_cidrs.get(sensor_id)
        if network is None:
            return True
        if isinstance(network, str):
            try:
                network = ipaddress.ip_network(network, strict=False)
            except ValueError:
                return False
        remote = remote_ip_address()
        return remote is not None and remote.version == network.version and remote in network

    def remote_is_sensor_network() -> bool:
        remote = remote_ip_address()
        if remote is None:
            return False
        for network in (app.config.get("SENSOR_SOURCE_CIDRS") or {}).values():
            if isinstance(network, str):
                try:
                    network = ipaddress.ip_network(network, strict=False)
                except ValueError:
                    continue
            if remote.version == network.version and remote in network:
                return True
        return False

    def sensor_authorization_error(sensor_id: str, raw_body: bytes) -> str | None:
        supplied_key = request.headers.get("X-Aegis-Key", "")
        supplied_sensor = request.headers.get("X-Aegis-Sensor", "")
        if supplied_sensor and supplied_sensor != sensor_id:
            return "unauthorized"
        if not sensor_source_allowed(sensor_id):
            return "unauthorized"
        # Check every accepted key without early exit so timing does not reveal
        # which one matched during an overlapping-key rotation.
        matching = [
            candidate for candidate in sensor_secrets(sensor_id)
            if hmac.compare_digest(candidate, supplied_key)
        ]
        if not matching:
            return "unauthorized"
        expected = matching[0]
        if app.config.get("REQUIRE_SENSOR_SIGNATURE"):
            nonce = request.headers.get("X-Aegis-Nonce", "")
            if not nonce:
                return "unauthorized"
            signature_valid = verify_signed_payload(
                expected,
                request.headers.get("X-Aegis-Timestamp", ""),
                request.headers.get("X-Aegis-Signature", ""),
                raw_body,
                int(app.config.get("SENSOR_SIGNATURE_MAX_SKEW", 300)),
                nonce,
            )
            if not signature_valid:
                return "unauthorized"
            if not store.reserve_sensor_nonce(
                sensor_id,
                nonce,
                window_seconds=int(app.config.get("SENSOR_SIGNATURE_MAX_SKEW", 300)),
                max_nonces_per_sensor=int(app.config.get("SENSOR_REPLAY_MAX_NONCES_PER_SENSOR", 4096)),
            ):
                return "sensor_replay_rejected"
        return None

    def _bump_counter(name: str) -> None:
        try:
            store.increment_counter(name)
        except Exception:
            app.logger.exception("counter increment failed")

    def _load_shed_response() -> tuple[Response, int] | None:
        # Shed ingest only when free disk is below the configured minimum, to
        # protect the database from a full disk. Dropping telemetry is explicit
        # evidence loss (counted); if disk cannot be read we do NOT shed, so we
        # never drop evidence on an unknown condition.
        threshold = int(app.config.get("MIN_FREE_BYTES", 67_108_864))
        try:
            free = shutil.disk_usage(Path(app.config["DATABASE_PATH"]).parent).free
        except OSError:
            return None
        if free >= threshold:
            return None
        _bump_counter("load_shed_events")
        app.logger.warning("aegis-load-shed: free_bytes=%d below min_free_bytes=%d", free, threshold)
        return jsonify({"error": "load_shed", "detail": "insufficient free storage; telemetry shed (evidence loss)"}), 503

    def sensor_auth_failure(sensor_id: str, raw_body: bytes) -> tuple[Response, int] | None:
        error = sensor_authorization_error(sensor_id, raw_body)
        if error is None:
            return None
        _bump_counter("sensor_replay_rejections" if error == "sensor_replay_rejected" else "sensor_auth_failures")
        return jsonify({"error": error}), 409 if error == "sensor_replay_rejected" else 401

    def _default_operator_identity() -> str:
        return str(app.config.get("OPERATOR_IDENTITY") or "operator")

    def resolve_operator_identity() -> str | None:
        """Return the authenticated operator name, or ``None`` if unauthorized.

        Named per-analyst keys (``OPERATOR_KEYS``) and the single shared/lab key
        (``OPERATOR_API_KEY`` plus its rotation predecessor) are both accepted so
        a deployment can move from one lab key to named identities without an
        outage. Named keys take precedence; the shared key resolves to the
        configured default identity. Every configured candidate is compared in
        constant time without an early exit to avoid leaking which identity (if
        any) matched.
        """
        named = app.config.get("OPERATOR_KEYS") or {}
        shared = str(app.config.get("OPERATOR_API_KEY", ""))
        if not named and not shared:
            # Single-key lab mode with no key configured: open only when a test
            # harness or the explicit development-only opt-in allows it.
            if bool(app.config.get("TESTING")) or bool(app.config.get("ALLOW_UNAUTHENTICATED_OPERATOR")):
                return _default_operator_identity()
            return None
        supplied = request.headers.get("X-Aegis-Operator-Key", "")
        if not supplied:
            return None
        matched: str | None = None
        for name, secret in named.items():
            if any([hmac.compare_digest(candidate, supplied) for candidate in _secret_candidates(secret)]):
                matched = matched or name
        if matched is not None:
            return matched
        if shared:
            accepted = _secret_candidates([shared, app.config.get("OPERATOR_API_KEY_PREVIOUS", "")])
            if any([hmac.compare_digest(candidate, supplied) for candidate in accepted]):
                return _default_operator_identity()
        return None

    def current_operator_identity() -> str | None:
        return getattr(g, "operator_identity", None)

    def record_audit(
        action: str,
        *,
        target_type: str = "",
        target_id: str = "",
        detail: dict | None = None,
        outcome: str = "success",
    ) -> None:
        """Append an operator action to the audit log, attributed to the caller.

        Auditing must never break the operation it records: the authenticated
        request already succeeded by the time this runs, so a logging failure is
        swallowed (and surfaced in the application log) rather than turned into a
        5xx that would hide the action without preventing it.
        """
        try:
            audit_log.record(
                current_operator_identity() or _default_operator_identity(),
                action,
                target_type=target_type,
                target_id=target_id,
                detail=detail,
                source_ip=request.remote_addr,
                outcome=outcome,
            )
        except Exception:  # pragma: no cover - defensive; audit must not 500 a request
            app.logger.exception("operator audit logging failed for action %s", action)

    def case_operator_audit(case_id: str) -> list[dict]:
        """Operator audit entries scoped to a single case for its report.

        Surfacing the append-only operator audit log (Cycle P) alongside the
        case's own history makes a case report a complete accountability record:
        who changed the case, linked or removed evidence, added notes or exported
        it, attributed to the authenticated operator. Reading the log must never
        break report generation, so a failure degrades to an empty list that the
        report still renders (and is surfaced in the application log).
        """
        try:
            return audit_log.list(target_type="case", target_id=case_id, limit=500)
        except Exception:  # pragma: no cover - defensive; report must not 500
            app.logger.exception("reading case operator audit failed for %s", case_id)
            return []

    def operator_authorized() -> bool:
        identity = resolve_operator_identity()
        g.operator_identity = identity
        return identity is not None

    @app.before_request
    def protect_trust_boundaries():
        sensor_ingest = (
            request.method == "POST"
            and request.path in {"/api/v1/events", "/api/v1/integrations/suricata/eve", "/api/v1/sensors/heartbeat", "/api/v1/quarantine"}
        )
        if remote_is_sensor_network() and not sensor_ingest:
            return jsonify({"error": "sensor_network_denied"}), 403
        if not request.path.startswith("/api/v1/"):
            return None
        if sensor_ingest:
            return None
        if request.path == "/api/v1/operator/status":
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
        probe = store.operational_health(int(app.config.get("MIN_FREE_BYTES", 67_108_864)))
        status = "ok" if probe["ready"] else "degraded"
        return jsonify({"status": status}), 200 if probe["ready"] else 503

    @app.get("/api/v1/operator/status")
    def operator_status():
        remote = request.remote_addr or "unknown"
        if not limiter.allow(f"operator-status:{remote}", 60, 60):
            return jsonify({"error": "rate_limited"}), 429
        authenticated = operator_authorized()
        named_operators = app.config.get("OPERATOR_KEYS") or {}
        shared_key_configured = bool(app.config.get("OPERATOR_API_KEY"))
        operator_key_configured = shared_key_configured or bool(named_operators)
        insecure_opt_in = bool(app.config.get("ALLOW_UNAUTHENTICATED_OPERATOR"))
        payload = {
            "required": operator_key_configured or not (bool(app.config.get("TESTING")) or insecure_opt_in),
            "configured": operator_key_configured,
            "authenticated": authenticated,
            "insecure_unauthenticated_opt_in": insecure_opt_in and not operator_key_configured,
        }
        if authenticated:
            # Attribute the session to a named operator so later audit logging and
            # case ownership (Cycle P/G) can record who acted. The roster itself is
            # never exposed to unauthenticated callers.
            if named_operators:
                payload["operator_auth_mode"] = "named_identities"
            elif shared_key_configured:
                payload["operator_auth_mode"] = "shared_key"
            else:
                payload["operator_auth_mode"] = "unauthenticated_lab"
            payload["operator"] = current_operator_identity() or _default_operator_identity()
            payload["operator_identity_count"] = len(named_operators)
            sensor_keys = app.config.get("SENSOR_KEYS") or {}
            payload["sensor_auth_mode"] = "per_sensor_allowlist" if sensor_keys else (
                "shared_key" if app.config.get("INGEST_API_KEY") else "unconfigured"
            )
            payload["sensor_allowlist_count"] = len(sensor_keys)
            payload["sensor_source_binding_count"] = len(app.config.get("SENSOR_SOURCE_CIDRS") or {})
        return jsonify(payload)

    @app.get("/api/v1/operations/status")
    def operations_status():
        health = store.operational_health(int(app.config.get("MIN_FREE_BYTES", 67_108_864)))
        telemetry = {
            "recent_hours": max(1, min(request.args.get("hours", 24, type=int), 720)),
            "configured_sensors": 0,
            "configured_with_recent_telemetry": 0,
            "observed_sensor_ids": 0,
            "items": [],
            "interpretation": "Telemetry freshness unavailable because the collector database is not ready.",
        }
        counters: dict = {}
        if health["database_ready"]:
            sensor_keys = app.config.get("SENSOR_KEYS") or {}
            telemetry = store.sensor_telemetry_observation(
                configured_sensor_ids=list(sensor_keys),
                recent_hours=request.args.get("hours", 24, type=int),
                heartbeat_stale_seconds=int(app.config.get("SENSOR_HEARTBEAT_STALE_SECONDS", 180)),
            )
            counters = store.counters()
        return jsonify({"collector": health, "telemetry": telemetry, "counters": counters})

    def _sensor_health_snapshot(database_ready: bool) -> dict:
        if not database_ready:
            return {}
        return store.sensor_health(
            configured_sensor_ids=list(app.config.get("SENSOR_KEYS") or {}),
            recent_hours=24,
            heartbeat_stale_seconds=int(app.config.get("SENSOR_HEARTBEAT_STALE_SECONDS", 180)),
        )

    @app.get("/api/v1/metrics")
    def platform_metrics():
        health = store.operational_health(int(app.config.get("MIN_FREE_BYTES", 67_108_864)))
        telemetry: dict = {}
        evidence_loss: dict | None = None
        snapshot = _sensor_health_snapshot(health["database_ready"])
        if snapshot:
            telemetry = {**snapshot["observation"], "silent_sensors_count": snapshot["silent_count"]}
        counters = None
        if health["database_ready"]:
            evidence_loss = store.evidence_loss_summary(hours=24)
            counters = store.counters()
        return Response(
            render_prometheus(health, telemetry, evidence_loss, counters),
            content_type=PROMETHEUS_CONTENT_TYPE,
        )

    @app.get("/api/v1/sensors/health")
    def sensors_health():
        health = store.operational_health(int(app.config.get("MIN_FREE_BYTES", 67_108_864)))
        snapshot = _sensor_health_snapshot(health["database_ready"])
        if not snapshot:
            return jsonify({
                "recent_hours": 24, "sensors": [], "silent_sensors": [], "silent_count": 0,
                "interpretation": "Sensor health unavailable because the collector database is not ready.",
            })
        snapshot.pop("observation", None)  # already summarized into the sensors list
        return jsonify(snapshot)

    @app.get("/api/v1/audit")
    def operator_audit():
        return jsonify({
            "retention_days": audit_log.retention_days,
            "max_rows": audit_log.max_rows,
            "items": audit_log.list(
                limit=request.args.get("limit", 200, type=int),
                operator=request.args.get("operator", type=str),
                action=request.args.get("action", type=str),
                target_type=request.args.get("target_type", type=str),
                target_id=request.args.get("target_id", type=str),
            ),
        })

    @app.post("/api/v1/sensors/heartbeat")
    def sensor_heartbeat():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        raw_body = request.get_data(cache=True)
        if len(raw_body) > 4096:
            return jsonify({"error": "payload_too_large"}), 413
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_json"}), 400
        sensor_id = str(payload.get("sensor_id") or "")[:96]
        auth_failure = sensor_auth_failure(sensor_id, raw_body) if sensor_id else None
        if not sensor_id or auth_failure is not None:
            if auth_failure is not None:
                return auth_failure
            return jsonify({"error": "unauthorized"}), 401
        remote = request.remote_addr or "unknown"
        if not limiter.allow(f"heartbeat:{sensor_id}:{remote}", 12, 60):
            return jsonify({"error": "rate_limited"}), 429
        sensor_timestamp = payload.get("timestamp")
        if sensor_timestamp is not None and not isinstance(sensor_timestamp, str):
            return jsonify({"error": "invalid_timestamp"}), 422
        try:
            event_sequence = validate_heartbeat_sequence(payload.get("event_sequence"))
        except SensorSequenceError as exc:
            return jsonify({"error": "invalid_event_sequence", "detail": str(exc)}), 422
        heartbeat = store.record_sensor_heartbeat(
            sensor_id,
            sensor_timestamp=sensor_timestamp,
            event_sequence=event_sequence,
        )
        return jsonify(heartbeat), 202

    @app.post("/api/v1/quarantine")
    def ingest_quarantine_artifact():
        sensor_id = (request.headers.get("X-Aegis-Sensor") or "")[:96]
        raw_body = request.get_data(cache=False)
        if len(raw_body) > int(app.config.get("QUARANTINE_MAX_BYTES", 262144)):
            return jsonify({"error": "artifact_too_large"}), 413
        if auth_failure := sensor_auth_failure(sensor_id, raw_body):
            return auth_failure
        if not limiter.allow(
            f"quarantine:{sensor_id}:{request.remote_addr or 'unknown'}",
            max(1, min(int(app.config.get("INGEST_RATE_LIMIT", 600)), 120)),
            60,
        ):
            return jsonify({"error": "rate_limited"}), 429
        try:
            artifact = quarantine_store.store(
                raw_body,
                sensor_id=sensor_id,
                original_name=request.headers.get("X-Aegis-Artifact-Name", ""),
                content_type=request.headers.get("X-Aegis-Artifact-Type", "application/octet-stream"),
            )
        except QuarantineError as exc:
            status = 413 if str(exc) == "artifact_too_large" else 422
            return jsonify({"error": str(exc)}), status
        except OSError:
            app.logger.exception("quarantine storage failed")
            return jsonify({"error": "quarantine_storage_failed"}), 500
        return jsonify(artifact), 201

    def record_detection_findings(stored: dict) -> None:
        for finding in detection_engine.evaluate(stored, store.detection_context(stored)):
            if detection_suppressions.match(finding):
                continue
            alert_store.record(finding, stored["timestamp"])
            forwarder.submit("alert", finding)

    @app.post("/api/v1/events")
    def ingest_event():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            raw_body = request.get_data(cache=True)
            if len(raw_body) > int(app.config.get("EVENT_MAX_BYTES", 65536)):
                return jsonify({"error": "payload_too_large"}), 413
            payload = request.get_json()
            sensor_id = str(payload.get("honeypot") or "")[:96] if isinstance(payload, dict) else ""
            if auth_failure := sensor_auth_failure(sensor_id, raw_body):
                return auth_failure
            if not limiter.allow(
                f"ingest:{sensor_id}:{request.remote_addr or 'unknown'}",
                int(app.config.get("INGEST_RATE_LIMIT", 600)),
                60,
            ):
                return jsonify({"error": "rate_limited"}), 429
            if shed := _load_shed_response():
                return shed
            event = normalize_event(payload)
            collector_received_at = utc_now_iso()
            validate_event_clock(
                event["timestamp"],
                collector_received_at,
                max_future_skew_seconds=int(app.config.get("MAX_FUTURE_EVENT_SKEW_SECONDS", 300)),
            )
            event = derive_observed_artifacts(event)
            event = enricher.enrich(event)
            event = threat_context.enrich(event)
            event = benign_scanners.enrich(event)
            stored = store.ingest(event, collector_received_at=collector_received_at)
            record_detection_findings(stored)
            forwarder.submit("event", stored)
        except sqlite3.IntegrityError:
            return jsonify({"error": "duplicate_event"}), 409
        except EventClockError as exc:
            _bump_counter("ingest_validation_rejections")
            return jsonify({"error": "clock_validation_error", "detail": str(exc)}), 422
        except EventValidationError as exc:
            _bump_counter("ingest_validation_rejections")
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
            if len(raw_body) > int(app.config.get("EVENT_MAX_BYTES", 65536)):
                return jsonify({"error": "payload_too_large"}), 413
            if auth_failure := sensor_auth_failure(sensor_id, raw_body):
                return auth_failure
            if not limiter.allow(
                f"suricata:{sensor_id}:{request.remote_addr or 'unknown'}",
                int(app.config.get("INGEST_RATE_LIMIT", 600)),
                60,
            ):
                return jsonify({"error": "rate_limited"}), 429
            event = normalize_event(normalize_eve_event(request.get_json(), sensor_id))
            collector_received_at = utc_now_iso()
            validate_event_clock(
                event["timestamp"],
                collector_received_at,
                max_future_skew_seconds=int(app.config.get("MAX_FUTURE_EVENT_SKEW_SECONDS", 300)),
            )
            event = derive_observed_artifacts(event)
            event = enricher.enrich(event)
            event = threat_context.enrich(event)
            event = benign_scanners.enrich(event)
            stored = store.ingest(event, collector_received_at=collector_received_at)
            record_detection_findings(stored)
            forwarder.submit("event", stored)
        except sqlite3.IntegrityError:
            return jsonify({"error": "duplicate_event"}), 409
        except EventClockError as exc:
            return jsonify({"error": "clock_validation_error", "detail": str(exc)}), 422
        except (SuricataValidationError, EventValidationError) as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except Exception:
            app.logger.exception("suricata ingestion failed")
            return jsonify({"error": "ingestion_failed"}), 500
        return jsonify({"id": stored["id"], "session_id": stored["session_id"]}), 201

    app.register_blueprint(
        make_pcap_blueprint(
            pcap_store=pcap_store,
            pcap_capture_provider=pcap_capture_provider,
            record_audit=record_audit,
        )
    )
    app.register_blueprint(
        make_activity_blueprint(
            store=store,
            filters_from_request=_filters_from_request,
            pagination_scope=_pagination_scope,
        )
    )
    app.register_blueprint(make_ips_blueprint(store=store))
    app.register_blueprint(
        make_detections_blueprint(detection_config=detection_config, alert_store=alert_store)
    )
    app.register_blueprint(
        make_status_blueprint(
            enricher=enricher,
            benign_scanners=benign_scanners,
            threat_context=threat_context,
        )
    )

    @app.get("/api/v1/analytics/events/<event_id>")
    def event_behavioral_analytics(event_id: str):
        event = store.get_event(event_id[:128])
        if not event:
            return jsonify({"error": "not_found"}), 404
        context = store.behavioral_context(event, days=30)
        result = behavioral_analytics.evaluate(
            event,
            context["events"],
            truncated=bool(context["analysis"]["truncated"]),
        )
        result["history"] = context["analysis"]
        return jsonify(result)

    @app.get("/api/v1/threat-context/stix")
    def threat_context_stix_export():
        indicator_reader = getattr(threat_context, "indicators", None)
        if not callable(indicator_reader):
            return jsonify({"error": "stix_export_not_supported_by_provider"}), 409
        source = str(
            getattr(threat_context, "source", None)
            or getattr(threat_context, "provider_id", None)
            or "threat-intelligence-provider"
        )[:256]
        try:
            sensitive_values = [
                secret
                for value in (app.config.get("SENSOR_KEYS") or {}).values()
                for secret in _secret_candidates(value)
            ]
            sensitive_values.extend([
                str(app.config.get("INGEST_API_KEY") or ""),
                str(app.config.get("INGEST_API_KEY_PREVIOUS") or ""),
                str(app.config.get("OPERATOR_API_KEY") or ""),
                str(app.config.get("OPERATOR_API_KEY_PREVIOUS") or ""),
            ])
            sensitive_values.extend([
                secret
                for value in (app.config.get("OPERATOR_KEYS") or {}).values()
                for secret in _secret_candidates(value)
            ])
            shareable_indicators = sanitize_shareable_indicators(
                indicator_reader(),
                internal_networks=list((app.config.get("SENSOR_SOURCE_CIDRS") or {}).values()),
                sensitive_values=sensitive_values,
            )
            bundle = export_stix_bundle(
                shareable_indicators,
                source=source,
                generated_at=getattr(threat_context, "generated_at", None),
                tlp=str(app.config.get("CTI_EXPORT_TLP") or "TLP:AMBER+STRICT"),
            )
        except ValueError:
            return jsonify({"error": "invalid_cti_export_tlp"}), 503
        payload = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
        record_audit(
            "export.stix",
            target_type="threat_context",
            detail={
                "format": "stix",
                "tlp": str(app.config.get("CTI_EXPORT_TLP") or "TLP:AMBER+STRICT"),
                "objects": len(bundle.get("objects") or []) if isinstance(bundle, dict) else None,
            },
        )
        return Response(
            payload,
            mimetype="application/stix+json",
            headers={"Content-Disposition": 'attachment; filename="aegis-threat-context.stix.json"'},
        )

    app.register_blueprint(
        make_analytics_blueprint(
            store=store,
            correlation_workspace=correlation_workspace,
            filters_from_request=_filters_from_request,
        )
    )
    app.register_blueprint(
        make_detection_management_blueprint(
            store=store,
            detection_config=detection_config,
            detection_backtester=detection_backtester,
            detection_suppressions=detection_suppressions,
        )
    )

    app.register_blueprint(make_alerts_blueprint(alert_store=alert_store, record_audit=record_audit))
    app.register_blueprint(
        make_iocs_blueprint(
            ioc_workspace=ioc_workspace,
            csv_safe=_csv_safe,
            record_audit=record_audit,
        )
    )

    app.register_blueprint(
        make_cases_blueprint(
            store=store,
            record_audit=record_audit,
            current_operator_identity=current_operator_identity,
            default_operator_identity=_default_operator_identity,
        )
    )

    app.register_blueprint(
        make_reports_blueprint(
            store=store,
            alert_store=alert_store,
            detection_config=detection_config,
            record_audit=record_audit,
            case_operator_audit=case_operator_audit,
            csv_safe=_csv_safe,
        )
    )

    return app


app = create_app()
