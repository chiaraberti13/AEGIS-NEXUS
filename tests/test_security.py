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
    assert status["required"] is True
    assert status["configured"] is True
    assert status["authenticated"] is False
    assert status["insecure_unauthenticated_opt_in"] is False
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


def test_sensor_identity_is_bound_to_configured_management_cidr(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "SENSOR_KEYS": {"ssh-decoy-01": "ssh-secret"},
        "SENSOR_SOURCE_CIDRS": {"ssh-decoy-01": "172.31.101.0/24"},
    })
    client = app.test_client()

    payload = {
        "id": str(uuid.uuid4()),
        "honeypot": "ssh-decoy-01",
        "event_type": "connection",
        "observed": {"source_ip": "203.0.113.150", "service": "ssh", "protocol": "tcp", "destination_port": 2222},
    }
    body, headers = _signed_request("ssh-secret", "ssh-decoy-01", payload)
    allowed = client.post(
        "/api/v1/events",
        data=body,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "172.31.101.22"},
    )
    assert allowed.status_code == 201

    payload["id"] = str(uuid.uuid4())
    body, headers = _signed_request("ssh-secret", "ssh-decoy-01", payload)
    denied = client.post(
        "/api/v1/events",
        data=body,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "172.31.102.22"},
    )
    assert denied.status_code == 401


def test_sensor_management_network_cannot_reach_operator_or_ui_surfaces(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "OPERATOR_API_KEY": "operator-secret",
        "SENSOR_SOURCE_CIDRS": {"ssh-decoy-01": "172.31.101.0/24"},
    })
    client = app.test_client()
    remote = {"REMOTE_ADDR": "172.31.101.30"}
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    dashboard = client.get("/api/v1/dashboard", headers=operator, environ_overrides=remote)
    assert dashboard.status_code == 403
    assert dashboard.get_json()["error"] == "sensor_network_denied"

    status = client.get("/api/v1/operator/status", headers=operator, environ_overrides=remote)
    assert status.status_code == 403
    assert status.get_json()["error"] == "sensor_network_denied"

    ui = client.get("/", environ_overrides=remote)
    assert ui.status_code == 403
    assert ui.get_json()["error"] == "sensor_network_denied"


def test_unmapped_host_integration_is_not_blocked_by_sensor_cidr_binding(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "SENSOR_KEYS": {
            "ssh-decoy-01": "ssh-secret",
            "suricata-01": "suricata-secret",
        },
        "SENSOR_SOURCE_CIDRS": {"ssh-decoy-01": "172.31.101.0/24"},
    })
    client = app.test_client()
    response = client.post(
        "/api/v1/integrations/suricata/eve",
        headers={"X-Aegis-Key": "suricata-secret", "X-Aegis-Sensor": "suricata-01"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        json={
            "event_type": "alert",
            "src_ip": "203.0.113.151",
            "dest_ip": "192.0.2.10",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {"signature": "CIDR binding fixture", "signature_id": 12001, "severity": 2},
        },
    )
    assert response.status_code == 201


def test_malformed_sensor_allowlist_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_SENSOR_KEYS", "{not-json")
    monkeypatch.setenv("AEGIS_INGEST_API_KEY", "legacy-shared-secret")
    with pytest.raises(ValueError, match="AEGIS_SENSOR_KEYS"):
        create_app({
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "aegis.db"),
        })


def test_non_object_sensor_allowlist_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_SENSOR_KEYS", '["ssh-secret"]')
    with pytest.raises(ValueError, match="JSON object"):
        create_app({
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "aegis.db"),
        })


def test_signed_sensor_heartbeat_is_source_bound_and_does_not_create_attack_event(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "heartbeat.db"),
        "SENSOR_KEYS": {"ssh-decoy-01": "ssh-secret"},
        "SENSOR_SOURCE_CIDRS": {"ssh-decoy-01": "172.31.101.0/24"},
        "REQUIRE_SENSOR_SIGNATURE": True,
        "SENSOR_HEARTBEAT_STALE_SECONDS": 180,
    })
    client = app.test_client()
    payload = {
        "sensor_id": "ssh-decoy-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    body, headers = _signed_request("ssh-secret", "ssh-decoy-01", payload)

    denied = client.post(
        "/api/v1/sensors/heartbeat",
        data=body,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "172.31.102.20"},
    )
    assert denied.status_code == 401

    accepted = client.post(
        "/api/v1/sensors/heartbeat",
        data=body,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "172.31.101.20"},
    )
    assert accepted.status_code == 202
    assert accepted.get_json()["status"] == "healthy"

    operator = {"X-Aegis-Operator-Key": ""}  # TESTING permits operator access without a configured key.
    status = client.get("/api/v1/operations/status", headers=operator).get_json()
    sensor = next(item for item in status["telemetry"]["items"] if item["sensor_id"] == "ssh-decoy-01")
    assert sensor["heartbeat_state"] == "healthy"
    assert sensor["recent_events"] == 0

    dashboard = client.get("/api/v1/dashboard?include_simulation=true", headers=operator).get_json()
    assert dashboard["totals"]["events"] == 0


def test_heartbeat_sensor_identity_must_match_signed_header(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "heartbeat-identity.db"),
        "SENSOR_KEYS": {"ssh-decoy-01": "ssh-secret", "web-decoy-01": "web-secret"},
        "REQUIRE_SENSOR_SIGNATURE": True,
    })
    client = app.test_client()
    payload = {"sensor_id": "web-decoy-01", "timestamp": datetime.now(timezone.utc).isoformat()}
    body, headers = _signed_request("ssh-secret", "ssh-decoy-01", payload)
    response = client.post("/api/v1/sensors/heartbeat", data=body, headers=headers)
    assert response.status_code == 401
