from datetime import datetime, timedelta, timezone

from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _event(ts, ip="203.0.113.10"):
    return normalize_event({
        "timestamp": ts,
        "honeypot": "ssh-1",
        "event_type": "connection",
        "observed": {"source_ip": ip, "service": "ssh", "protocol": "tcp", "destination_port": 22},
    })


def test_session_correlation_respects_inactivity_gap(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = store.ingest(_event(start.isoformat()))
    second = store.ingest(_event((start + timedelta(minutes=10)).isoformat()))
    third = store.ingest(_event((start + timedelta(minutes=40)).isoformat()))
    assert first["session_id"] == second["session_id"]
    assert third["session_id"] != first["session_id"]


def test_relations_only_use_present_data(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot":"ssh-1",
        "event_type":"command",
        "observed":{"source_ip":"203.0.113.8","service":"ssh","command":"uname -a"},
        "derived":{"mitre":[{"technique_id":"T1059","rationale":"Command interpreter activity observed","evidence":["observed.command"]}]}
    })
    saved = store.ingest(event)
    graph = store.relations(saved["session_id"])
    kinds = {node["kind"] for node in graph["nodes"]}
    assert "mitre" in kinds
    assert "cve" not in kinds


def test_report_keeps_evidence_backed_mappings(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot":"web-1",
        "event_type":"payload",
        "observed":{"source_ip":"203.0.113.9","service":"http","payload":"example"},
        "derived":{"cve":[{"cve_id":"CVE-2099-0001","rationale":"Test fixture only","evidence":["observed.payload"]}]},
    })
    saved = store.ingest(event)
    report = store.report(saved["session_id"])
    assert report["evidence_backed_mappings"][0]["family"] == "cve"
    assert report["facts"]["event_count"] == 1


def test_session_correlation_separates_destination_ports(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = normalize_event({
        "timestamp": start.isoformat(),
        "honeypot": "multi-1",
        "event_type": "connection",
        "observed": {"source_ip":"203.0.113.20","service":"tcp","protocol":"tcp","destination_port":22},
    })
    second = normalize_event({
        "timestamp": (start + timedelta(minutes=1)).isoformat(),
        "honeypot": "multi-1",
        "event_type": "connection",
        "observed": {"source_ip":"203.0.113.20","service":"tcp","protocol":"tcp","destination_port":23},
    })
    a = store.ingest(first)
    b = store.ingest(second)
    assert a["session_id"] != b["session_id"]


def test_relationship_payload_labels_are_bounded(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot":"web-1",
        "event_type":"web.payload",
        "observed":{"source_ip":"203.0.113.30","service":"http","protocol":"tcp","destination_port":80,"payload":"A"*1000},
    })
    saved = store.ingest(event)
    graph = store.relations(saved["session_id"])
    payloads = [node for node in graph["nodes"] if node["kind"] == "payload"]
    assert payloads
    assert len(payloads[0]["label"]) <= 180


def test_ip_profile_keeps_external_enrichment_provenance(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.40",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "enrichment": {
            "geo": {
                "source": "geo-fixture",
                "observed_at": "2026-09-22T18:00:00Z",
                "data": {"country": "IT", "latitude": 41.9, "longitude": 12.5},
            }
        },
    })
    store.ingest(event)
    profile = store.ip_profile("203.0.113.40")
    assert profile["countries"] == ["IT"]
    assert profile["threat_intelligence"][0]["source"] == "geo-fixture"
    assert profile["threat_intelligence"][0]["provenance"] == "external_enrichment"


def test_report_never_exports_cleartext_password(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STORE_CREDENTIAL_SECRETS", "true")
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.41",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "credential": {"username": "root", "password": "cleartext-fixture"},
        },
    })
    saved = store.ingest(event)
    report = store.report(saved["session_id"])
    credential = report["credentials"][0]
    assert credential["username"] == "root"
    assert "password" not in credential
    assert credential["password_sha256"]


def test_case_references_survive_source_retention_without_copying_payload(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.90",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
            "payload": "sensitive-fixture-payload",
        },
    })
    saved = store.ingest(event)
    case = store.create_case({
        "title": "Web investigation",
        "summary": "Analyst working notes",
        "status": "open",
        "severity": "medium",
        "tags": ["web", "triage"],
    })
    case = store.add_case_evidence(case["id"], "event", saved["id"])
    assert case["evidence"][0]["available"] is True
    assert "sensitive-fixture-payload" not in str(case["evidence"][0]["summary"])

    with store.connect() as conn:
        conn.execute("DELETE FROM events WHERE id=?", (saved["id"],))
        conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")

    retained_case = store.get_case(case["id"])
    assert retained_case["evidence"][0]["available"] is False
    assert retained_case["evidence"][0]["evidence_id"] == saved["id"]


def test_case_audit_notes_and_analyst_classification(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.91",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    })
    saved = store.ingest(event)
    case = store.create_case({
        "title": "SSH review",
        "summary": "",
        "status": "open",
        "severity": "low",
        "tags": ["ssh"],
    })
    store.add_case_evidence(case["id"], "session", saved["session_id"])
    store.add_case_note(case["id"], "Review adjacent activity before escalation.")
    updated = store.update_case(case["id"], {"status": "investigating", "severity": "high", "tags": ["ssh", "priority"]})
    report = store.case_report(case["id"])

    assert updated["classification_provenance"] == "analyst"
    assert updated["status"] == "investigating"
    assert report["case"]["classification_provenance"] == "analyst"
    assert report["notes"][0]["provenance"] == "analyst_note"
    actions = [item["action"] for item in report["history"]]
    assert actions == ["created", "evidence_added", "note_added", "updated"]
