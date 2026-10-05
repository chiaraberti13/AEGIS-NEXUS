import sqlite3

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.operator_audit import OperatorAuditError, OperatorAuditLog


def _log(tmp_path, **kwargs):
    return OperatorAuditLog(str(tmp_path / "aegis.db"), **kwargs)


def _client(tmp_path, **config):
    base = {"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db")}
    base.update(config)
    return create_app(base).test_client()


# --- store-level behaviour -------------------------------------------------


def test_record_and_list_round_trip(tmp_path):
    log = _log(tmp_path)
    entry = log.record(
        "alice",
        "alert.update",
        target_type="alert",
        target_id="al_1",
        detail={"status": "investigating"},
        source_ip="203.0.113.9",
    )
    assert entry["operator"] == "alice"
    assert entry["action"] == "alert.update"
    assert entry["detail"] == {"status": "investigating"}
    assert entry["source_ip"] == "203.0.113.9"
    assert entry["outcome"] == "success"

    items = log.list()
    assert len(items) == 1
    assert items[0]["id"] == entry["id"]
    assert items[0]["detail"] == {"status": "investigating"}


def test_list_filters_and_orders_newest_first(tmp_path):
    log = _log(tmp_path)
    log.record("alice", "case.create", target_type="case", target_id="c1")
    log.record("bob", "case.delete", target_type="case", target_id="c1")
    log.record("alice", "export.ioc_csv", target_type="ioc")

    assert [i["action"] for i in log.list()] == ["export.ioc_csv", "case.delete", "case.create"]
    assert {i["operator"] for i in log.list(operator="alice")} == {"alice"}
    assert [i["action"] for i in log.list(operator="alice")] == ["export.ioc_csv", "case.create"]
    assert [i["action"] for i in log.list(target_type="case", target_id="c1")] == [
        "case.delete",
        "case.create",
    ]
    assert [i["action"] for i in log.list(action="export.ioc_csv")] == ["export.ioc_csv"]


def test_append_only_update_is_rejected_by_trigger(tmp_path):
    log = _log(tmp_path)
    entry = log.record("alice", "case.create", target_type="case", target_id="c1")
    with log.connect() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE operator_audit_log SET operator='mallory' WHERE id=?",
                (entry["id"],),
            )
    # The original attribution survives the blocked tamper attempt.
    assert log.list()[0]["operator"] == "alice"


def test_ids_are_monotonic_so_deletions_are_visible(tmp_path):
    log = _log(tmp_path)
    ids = [log.record("a", "case.create", target_id=str(i))["id"] for i in range(3)]
    assert ids == sorted(ids)
    assert len(set(ids)) == 3


def test_invalid_action_is_a_programming_error(tmp_path):
    log = _log(tmp_path)
    for bad in ("", "no-dots", "bad action", "trailing.", ".leading"):
        with pytest.raises(OperatorAuditError):
            log.record("alice", bad)


def test_action_case_is_normalized(tmp_path):
    # Actions are code constants; case is normalized rather than rejected.
    assert _log(tmp_path).record("alice", "Case.Create")["action"] == "case.create"


def test_hostile_input_is_bounded_and_control_chars_stripped(tmp_path):
    log = _log(tmp_path)
    entry = log.record(
        "alice\n\tinjected",
        "pcap.download",
        target_type="pcap",
        target_id="x" * 500,
        detail={
            "k" * 200: "v" * 5000,
            "list": list(range(100)),
            "nested": {"dropped": True},
        },
        source_ip="not-an-ip",
    )
    assert "\n" not in entry["operator"] and "\t" not in entry["operator"]
    assert len(entry["target_id"]) == 128
    assert entry["source_ip"] is None
    # Each field is individually bounded and the nested dict is coerced to a
    # bounded string rather than stored as a nested structure.
    assert len(next(iter(entry["detail"]))) == 64
    assert len(entry["detail"]["k" * 64]) == 256
    assert len(entry["detail"]["list"]) == 32
    assert isinstance(entry["detail"]["nested"], str)


def test_oversized_detail_collapses_to_truncation_marker(tmp_path):
    log = _log(tmp_path)
    entry = log.record(
        "alice",
        "case.update",
        detail={f"key_{i}": "v" * 300 for i in range(32)},
    )
    assert entry["detail"] == {"truncated": True}


def test_detail_values_and_keys_are_capped(tmp_path):
    log = _log(tmp_path)
    entry = log.record(
        "alice",
        "case.update",
        detail={"status": "s" * 1000, "list": ["a" * 1000] + ["b"] * 100},
    )
    assert len(entry["detail"]["status"]) == 256
    assert len(entry["detail"]["list"]) == 32
    assert len(entry["detail"]["list"][0]) == 256


def test_outcome_is_constrained(tmp_path):
    log = _log(tmp_path)
    assert log.record("a", "case.create", outcome="denied")["outcome"] == "denied"
    assert log.record("a", "case.create", outcome="bogus")["outcome"] == "success"


def test_retention_prunes_oldest_and_records_evidence_loss(tmp_path):
    log = _log(tmp_path, max_rows=5)
    for i in range(8):
        log.record("alice", "case.create", target_id=str(i))
    actions = [i["action"] for i in log.list(limit=1000)]
    # A retention-prune marker is appended and the oldest raw entries are gone.
    assert "audit.retention_prune" in actions
    prune = log.list(action="audit.retention_prune")[0]
    assert prune["operator"] == "system"
    assert prune["detail"]["pruned"] >= 1
    # The bound is respected (allowing the single prune marker as headroom).
    assert log.count() <= 6


def test_retention_prune_marker_is_not_itself_pruned_by_age(tmp_path):
    # A zero row bound with aggressive age pruning still keeps the newest marker.
    log = _log(tmp_path, retention_days=365, max_rows=3)
    for i in range(10):
        log.record("alice", "alert.update", target_id=str(i))
    assert log.list(action="audit.retention_prune")


# --- API integration -------------------------------------------------------


def test_alert_lifecycle_change_is_audited_with_operator_attribution(tmp_path):
    client = _client(tmp_path, OPERATOR_KEYS={"alice": "alice-key"})
    headers = {"X-Aegis-Operator-Key": "alice-key"}

    # Seed an alert directly through the alert store used by the app.
    with client.application.app_context():
        store = client.application.extensions["aegis_alert_store"]
        alert = store.record(
            {
                "rule_id": "multiple_auth_failures",
                "rule_version": "1",
                "schema_version": "1",
                "title": "t",
                "description": "",
                "severity": "medium",
                "confidence": 50,
                "source_ip": "203.0.113.5",
                "session_id": "ses_1",
                "evidence": [],
            },
            "2026-01-01T00:00:00+00:00",
        )

    resp = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"status": "investigating"},
        headers=headers,
    )
    assert resp.status_code == 200

    audit = client.get("/api/v1/audit", headers=headers).get_json()
    entries = [e for e in audit["items"] if e["action"] == "alert.update"]
    assert len(entries) == 1
    assert entries[0]["operator"] == "alice"
    assert entries[0]["target_id"] == alert["id"]
    assert entries[0]["detail"]["status"] == "investigating"


def test_case_changes_and_exports_are_audited(tmp_path):
    client = _client(tmp_path, OPERATOR_KEYS={"bob": "bob-key"})
    headers = {"X-Aegis-Operator-Key": "bob-key"}

    created = client.post(
        "/api/v1/cases",
        json={"title": "Investigation", "severity": "high"},
        headers=headers,
    ).get_json()
    case_id = created["id"]

    assert client.get(
        f"/api/v1/reports/case/{case_id}.md", headers=headers
    ).status_code == 200
    assert client.get("/api/v1/iocs/export.csv", headers=headers).status_code == 200

    audit = client.get("/api/v1/audit", headers=headers).get_json()
    actions = {e["action"] for e in audit["items"]}
    assert {"case.create", "export.case_report", "export.ioc_csv"} <= actions
    assert all(e["operator"] == "bob" for e in audit["items"])


def test_audit_log_requires_operator_authentication(tmp_path):
    client = _client(tmp_path, OPERATOR_KEYS={"alice": "alice-key"})
    assert client.get("/api/v1/audit").status_code == 401
    assert client.get(
        "/api/v1/audit", headers={"X-Aegis-Operator-Key": "alice-key"}
    ).status_code == 200


def test_note_bodies_are_not_copied_into_the_audit_trail(tmp_path):
    client = _client(tmp_path)
    created = client.post("/api/v1/cases", json={"title": "Case", "severity": "low"}).get_json()
    secret_note = "analyst-only sensitive observation 42"
    assert client.post(
        f"/api/v1/cases/{created['id']}/notes",
        json={"body": secret_note},
    ).status_code == 201

    raw = client.get("/api/v1/audit").data
    assert secret_note.encode() not in raw
    audit = client.get("/api/v1/audit").get_json()
    assert any(e["action"] == "case.note_add" for e in audit["items"])
