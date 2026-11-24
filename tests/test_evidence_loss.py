from __future__ import annotations

from aegis_nexus.app import create_app
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _ingest(store, command):
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": command},
    })
    store.ingest(event, collector_received_at=event["timestamp"])


def test_evidence_loss_summary_counts_truncation(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    _ingest(store, "A" * 5000)  # exceeds MAX_STRING -> truncated, lossy

    summary = store.evidence_loss_summary(hours=24)
    assert summary["events_considered"] == 1
    assert summary["counts"].get("truncated_strings", 0) >= 1
    assert summary["counts"].get("events_with_truncation", 0) >= 1


def test_evidence_loss_summary_clean_event_has_no_loss(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    _ingest(store, "id")
    summary = store.evidence_loss_summary(hours=24)
    assert summary["events_considered"] == 1
    assert summary["counts"].get("truncated_strings", 0) == 0
    assert summary["counts"].get("events_with_truncation", 0) == 0


def test_metrics_expose_evidence_loss_gauges(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={"honeypot": "ssh-1", "event_type": "command",
              "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                           "destination_port": 22, "command": "A" * 5000}},
    )
    body = client.get("/api/v1/metrics", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_data(as_text=True)
    assert "aegis_evidence_loss_events_considered 1" in body
    assert "aegis_evidence_events_with_truncation" in body
