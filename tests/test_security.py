import json
import time
import uuid

import pytest
from datetime import datetime, timezone

from aegis_nexus.app import create_app
from aegis_nexus.model import EventValidationError, normalize_event
from aegis_nexus.security import SlidingWindowLimiter, sign_payload, verify_signed_payload
from aegis_nexus.store import Store


def _signed_request(secret: str, sensor: str, payload: dict):
    body = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Aegis-Key": secret,
        "X-Aegis-Sensor": sensor,
        "X-Aegis-Timestamp": timestamp,
        "X-Aegis-Signature": sign_payload(secret, timestamp, body),
    }
    return body, headers


def test_normalize_event_rejects_non_finite_numeric_values():
    with pytest.raises(EventValidationError, match="non-finite"):
        normalize_event({
            "honeypot": "web-1",
            "event_type": "web.request",
            "observed": {"source_ip": "203.0.113.90", "score": float("nan")},
        })


def test_signature_verification_and_tamper_detection():
    body = b'{"event":"example"}'
    timestamp = str(int(time.time()))
    signature = sign_payload("secret", timestamp, body)
    assert verify_signed_payload("secret", timestamp, signature, body, 300)
    assert not verify_signed_payload("secret", timestamp, signature, body + b"x", 300)
    assert not verify_signed_payload("wrong", timestamp, signature, body, 300)


def test_signed_ingest_rejects_replay(tmp_path):
    secret = "sensor-secret"
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": secret,
        "REQUIRE_SENSOR_SIGNATURE": True,
    })
    client = app.test_client()
    payload = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "honeypot": "ssh-decoy-01",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.91",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    }
    body, headers = _signed_request(secret, "ssh-decoy-01", payload)
    assert client.post("/api/v1/events", data=body, headers=headers).status_code == 201
    assert client.post("/api/v1/events", data=body, headers=headers).status_code == 409


def test_signed_ingest_rejects_bad_signature(tmp_path):
    secret = "sensor-secret"
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": secret,
        "REQUIRE_SENSOR_SIGNATURE": True,
    })
    client = app.test_client()
    payload = {
        "id": str(uuid.uuid4()),
        "honeypot": "ssh-decoy-01",
        "event_type": "connection",
        "observed": {"source_ip": "203.0.113.92"},
    }
    body, headers = _signed_request(secret, "ssh-decoy-01", payload)
    headers["X-Aegis-Signature"] = "0" * 64
    assert client.post("/api/v1/events", data=body, headers=headers).status_code == 401


def test_operator_api_fails_closed_without_key_outside_testing(tmp_path):
    app = create_app({
        "TESTING": False,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "OPERATOR_API_KEY": "",
        "ALLOW_UNAUTHENTICATED_OPERATOR": False,
    })
    client = app.test_client()
    status = client.get("/api/v1/operator/status").get_json()
    assert status["required"] is True
    assert status["configured"] is False
    assert status["authenticated"] is False
    assert status["insecure_unauthenticated_opt_in"] is False
    assert client.get("/api/v1/dashboard").status_code == 401


def test_operator_api_allows_explicit_unauthenticated_development_opt_in(tmp_path):
    app = create_app({
        "TESTING": False,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "OPERATOR_API_KEY": "",
        "ALLOW_UNAUTHENTICATED_OPERATOR": True,
    })
    client = app.test_client()
    status = client.get("/api/v1/operator/status").get_json()
    assert status["required"] is False
    assert status["configured"] is False
    assert status["authenticated"] is True
    assert status["insecure_unauthenticated_opt_in"] is True
    assert client.get("/api/v1/dashboard").status_code == 200


def test_operator_api_is_protected_when_key_is_configured(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    status = client.get("/api/v1/operator/status").get_json()
    assert status == {"required": True, "authenticated": False}
    assert client.get("/api/v1/dashboard").status_code == 401
    headers = {"X-Aegis-Operator-Key": "operator-secret"}
    authenticated = client.get("/api/v1/operator/status", headers=headers).get_json()
    assert authenticated["authenticated"] is True
    assert client.get("/api/v1/dashboard", headers=headers).status_code == 200


def test_operator_rate_limit_is_bounded(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "OPERATOR_API_KEY": "operator-secret",
        "OPERATOR_RATE_LIMIT": 1,
    })
    client = app.test_client()
    headers = {"X-Aegis-Operator-Key": "operator-secret"}
    assert client.get("/api/v1/dashboard", headers=headers).status_code == 200
    assert client.get("/api/v1/dashboard", headers=headers).status_code == 429


def test_sliding_window_limiter_blocks_excess_requests():
    limiter = SlidingWindowLimiter()
    assert limiter.allow("sensor", 2, 60)
    assert limiter.allow("sensor", 2, 60)
    assert not limiter.allow("sensor", 2, 60)


def test_dashboard_discloses_when_analysis_is_truncated(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.analytics_max_events = 2
    now = datetime.now(timezone.utc).isoformat()
    for index in range(3):
        store.ingest(normalize_event({
            "timestamp": now,
            "honeypot": "web-1",
            "event_type": "connection",
            "observed": {
                "source_ip": f"203.0.113.{100 + index}",
                "service": "http",
                "protocol": "tcp",
                "destination_port": 80,
            },
        }))
    dashboard = store.dashboard(hours=24, include_simulation=True)
    assert dashboard["analysis"]["truncated"] is True
    assert dashboard["analysis"]["event_limit"] == 2
    assert dashboard["totals"]["events"] == 2
