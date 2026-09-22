from datetime import datetime, timedelta, timezone
import sqlite3

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
    assert profile["external_enrichment"][0]["source"] == "geo-fixture"
    assert profile["external_enrichment"][0]["provenance"] == "external_enrichment"
    assert profile["external_enrichment"][0]["classification"] == "context_enrichment"
    assert profile["threat_intelligence"] == []


def test_relations_expose_provenance_and_safe_credential_fingerprint(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.42",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "credential": {"username": "admin", "password": "reuse-me"},
        },
        "enrichment": {
            "threat_context": {
                "source": "fixture-feed",
                "observed_at": "2026-09-22T18:00:00Z",
                "data": {
                    "match_policy": "exact",
                    "matches": [{"type": "ip", "value": "203.0.113.42", "confidence": 70, "evidence": ["observed.source_ip"]}],
                },
            }
        },
    })
    saved = store.ingest(event)
    graph = store.relations(saved["session_id"])
    nodes = graph["nodes"]
    secret = next(node for node in nodes if node["kind"] == "credential_secret_fingerprint")
    assert secret["provenance"] == "derived"
    assert "reuse-me" not in str(graph)
    threat = next(node for node in nodes if node["kind"] == "threat_intel")
    assert threat["provenance"] == "enrichment"
    assert threat["metadata"]["source"] == "fixture-feed"
    ip = next(node for node in nodes if node["kind"] == "ip")
    assert ip["provenance"] == "observed"


def test_dashboard_exposes_investigation_dimensions_and_aggregates_geo_points(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    timestamp = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
    for event_type, payload in [
        ("credential", {
            "credential": {"username": "admin", "password": "same-secret"},
        }),
        ("web.payload", {
            "payload": "curl https://example.org/dropper",
        }),
    ]:
        observed = {
            "source_ip": "203.0.113.55",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 8080,
            **payload,
        }
        event = normalize_event({
            "timestamp": timestamp,
            "honeypot": "web-1",
            "event_type": event_type,
            "severity": "high" if event_type == "web.payload" else "medium",
            "observed": observed,
            "enrichment": {
                "geo": {
                    "source": "geo-fixture",
                    "observed_at": timestamp,
                    "data": {"country": "IT", "latitude": 41.9, "longitude": 12.5},
                },
                "asn": {
                    "source": "asn-fixture",
                    "observed_at": timestamp,
                    "data": {"asn": "AS64500"},
                },
            },
            "derived": {
                "cve": [{
                    "cve_id": "CVE-2099-0002",
                    "rationale": "Synthetic evidence-backed fixture only.",
                    "evidence": ["observed.payload"],
                }]
            } if event_type == "web.payload" else {},
        })
        store.ingest(event)

    dashboard = store.dashboard(hours=24, include_simulation=True)
    assert dashboard["totals"]["events"] == 2
    assert dashboard["source_ip"][0] == {"label": "203.0.113.55", "value": 2}
    assert dashboard["unique_source_ip_timeline"][0]["value"] == 1
    assert dashboard["credentials"][0]["label"] == "admin"
    assert dashboard["credential_secret_fingerprints"]
    assert "same-secret" not in str(dashboard)
    assert dashboard["payloads"][0]["value"] == 1
    assert dashboard["cves"] == [{"label": "CVE-2099-0002", "value": 1}]
    assert dashboard["map_points"][0]["count"] == 2
    assert dashboard["map_points"][0]["session_count"] == 1
    assert dashboard["analysis"]["provenance"]["hypotheses_in_analytics"] is False


def test_session_investigation_is_bounded_and_discloses_truncation(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), session_max_events=100)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    session_id = None
    for index in range(101):
        saved = store.ingest(normalize_event({
            "timestamp": timestamp,
            "honeypot": "ssh-1",
            "event_type": "connection",
            "observed": {
                "source_ip": "203.0.113.77",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "sensor_session_id": "bounded-session-1",
                "sequence": index,
            },
        }))
        session_id = saved["session_id"]

    bundle = store.get_session(session_id)
    assert bundle is not None
    assert len(bundle["events"]) == 100
    assert bundle["summary"]["truncated"] is True
    assert bundle["analysis"] == {
        "truncated": True,
        "event_limit": 100,
        "scope": "latest_session_events",
    }

    graph = store.relations(session_id)
    assert graph["analysis"]["truncated"] is True
    report = store.report(session_id)
    assert report is not None
    assert report["analysis"]["truncated"] is True
    assert any("not a complete" in item for item in report["limitations"])


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
    assert "cleartext-fixture" not in str(report)
    exported_credential = report["events"][0]["observed"]["credential"]
    assert "password" not in exported_credential
    assert exported_credential["password_sha256"]


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

    # Re-linking the same source evidence is idempotent and must not forge audit activity.
    store.add_case_evidence(case["id"], "session", saved["session_id"])
    after_duplicate = store.case_report(case["id"])
    duplicate_actions = [item["action"] for item in after_duplicate["history"]]
    assert duplicate_actions == actions


def test_explicit_sensor_session_id_prevents_temporal_merging(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def explicit(ts, token):
        return normalize_event({
            "timestamp": ts,
            "honeypot": "ssh-1",
            "event_type": "connection",
            "observed": {
                "source_ip": "203.0.113.100",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "sensor_session_id": token,
            },
        })

    first = store.ingest(explicit(start.isoformat(), "conn-a"))
    second = store.ingest(explicit((start + timedelta(minutes=1)).isoformat(), "conn-b"))
    later_same = store.ingest(explicit((start + timedelta(hours=4)).isoformat(), "conn-a"))

    assert first["session_id"] != second["session_id"]
    assert first["session_id"] == later_same["session_id"]
    assert first["session_id"].startswith("sesx_")
    bundle = store.get_session(first["session_id"])
    assert bundle["summary"]["correlation_method"] == "sensor_connection_id"
    assert bundle["session"]["event_count"] == 2


def test_explicit_session_handles_out_of_order_events(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = normalize_event({
        "timestamp": (start + timedelta(minutes=5)).isoformat(),
        "honeypot": "ftp-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.101",
            "service": "ftp",
            "protocol": "tcp",
            "destination_port": 21,
            "sensor_session_id": "ftp-conn",
        },
    })
    earlier = normalize_event({
        "timestamp": start.isoformat(),
        "honeypot": "ftp-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.101",
            "service": "ftp",
            "protocol": "tcp",
            "destination_port": 21,
            "sensor_session_id": "ftp-conn",
        },
    })
    a = store.ingest(later)
    b = store.ingest(earlier)
    assert a["session_id"] == b["session_id"]
    bundle = store.get_session(a["session_id"])
    assert bundle["session"]["started_at"] == start.isoformat()
    assert bundle["session"]["last_seen"] == (start + timedelta(minutes=5)).isoformat()


def test_suricata_flow_id_is_used_as_explicit_correlation(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def flow(ts, flow_start):
        return normalize_event({
            "timestamp": ts,
            "honeypot": "suricata-01",
            "event_type": "ids.alert",
            "observed": {
                "source_ip": "203.0.113.102",
                "destination_ip": "192.0.2.2",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "flow_id": 123456,
                "flow_start": flow_start,
            },
        })

    first = store.ingest(flow(start.isoformat(), "2026-01-01T00:00:00Z"))
    same = store.ingest(flow((start + timedelta(hours=2)).isoformat(), "2026-01-01T00:00:00Z"))
    reused_after_restart = store.ingest(flow((start + timedelta(hours=3)).isoformat(), "2026-01-01T03:00:00Z"))

    assert first["session_id"] == same["session_id"]
    assert reused_after_restart["session_id"] != first["session_id"]
    bundle = store.get_session(first["session_id"])
    assert bundle["summary"]["correlation_method"] == "suricata_flow_id"


def test_case_capacity_and_closed_case_retention(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), max_cases=2, case_retention_days=30)
    first = store.create_case({
        "title": "Open case",
        "summary": "",
        "status": "open",
        "severity": "low",
        "tags": [],
    })
    second = store.create_case({
        "title": "Closed case",
        "summary": "",
        "status": "closed",
        "severity": "info",
        "tags": [],
    })

    with store.connect() as conn:
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        conn.execute("UPDATE cases SET closed_at=?, updated_at=? WHERE id=?", (old, old, second["id"]))

    deleted = store.prune_cases()
    assert deleted == 1
    assert store.get_case(second["id"]) is None
    assert store.get_case(first["id"]) is not None

    replacement = store.create_case({
        "title": "Replacement",
        "summary": "",
        "status": "open",
        "severity": "info",
        "tags": [],
    })
    assert replacement["id"]

    try:
        store.create_case({
            "title": "Over capacity",
            "summary": "",
            "status": "open",
            "severity": "info",
            "tags": [],
        })
        assert False, "expected case_capacity"
    except ValueError as exc:
        assert str(exc) == "case_capacity"


def test_closed_case_delete_cascades_case_data_but_preserves_source_telemetry(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.150",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    })
    saved = store.ingest(event)
    case = store.create_case({
        "title": "Lifecycle case",
        "summary": "temporary analyst context",
        "status": "open",
        "severity": "medium",
        "tags": ["lifecycle"],
    })
    store.add_case_evidence(case["id"], "event", saved["id"])
    store.add_case_note(case["id"], "temporary note")

    assert store.delete_case(case["id"]) == "case_not_closed"
    store.update_case(case["id"], {"status": "closed"})
    assert store.delete_case(case["id"]) == "deleted"
    assert store.get_case(case["id"]) is None
    assert store.get_event(saved["id"]) is not None

    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM case_tags WHERE case_id=?", (case["id"],)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM case_evidence WHERE case_id=?", (case["id"],)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM case_notes WHERE case_id=?", (case["id"],)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM case_history WHERE case_id=?", (case["id"],)).fetchone()[0] == 0


def test_retention_uses_collector_receive_time_not_sensor_timestamp(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), retention_days=1)
    now = datetime.now(timezone.utc)
    historical = normalize_event({
        "id": "51000000-0000-4000-8000-000000000001",
        "timestamp": "2020-01-01T00:00:00Z",
        "honeypot": "archive-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.221",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    })
    saved = store.ingest(historical, collector_received_at=now.isoformat())
    assert saved["collector_received_at"] == now.isoformat()
    assert store.prune(1) == 0
    assert store.get_event(historical["id"]) is not None

    stale_receipt = normalize_event({
        "id": "51000000-0000-4000-8000-000000000002",
        "timestamp": now.isoformat(),
        "honeypot": "archive-2",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.222",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
    })
    store.ingest(stale_receipt, collector_received_at=(now - timedelta(days=2)).isoformat())
    assert store.prune(1) == 1
    assert store.get_event(stale_receipt["id"]) is None
    assert store.get_event(historical["id"]) is not None


def test_capacity_evicts_by_collector_receive_time(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), retention_days=0)
    store.max_events = 2

    fixtures = [
        ("52000000-0000-4000-8000-000000000001", "2026-01-01T00:00:00Z", "2026-09-22T20:03:00+00:00"),
        ("52000000-0000-4000-8000-000000000002", "2026-03-01T00:00:00Z", "2026-09-22T20:01:00+00:00"),
        ("52000000-0000-4000-8000-000000000003", "2026-02-01T00:00:00Z", "2026-09-22T20:02:00+00:00"),
    ]
    for index, (event_id, sensor_time, received_time) in enumerate(fixtures):
        event = normalize_event({
            "id": event_id,
            "timestamp": sensor_time,
            "honeypot": f"capacity-{index}",
            "event_type": "connection",
            "observed": {
                "source_ip": f"203.0.113.{230 + index}",
                "service": "tcp",
                "protocol": "tcp",
                "destination_port": 10000 + index,
            },
        })
        store.ingest(event, collector_received_at=received_time)

    result = store.maintain(force=True)
    assert result["capacity_deleted"] == 1
    assert store.get_event("52000000-0000-4000-8000-000000000002") is None
    assert store.get_event("52000000-0000-4000-8000-000000000001") is not None
    assert store.get_event("52000000-0000-4000-8000-000000000003") is not None


def test_existing_database_backfills_collector_receive_time_from_sensor_timestamp(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, honeypot TEXT NOT NULL,
            service TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'unknown',
            destination_port INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL, last_seen TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE events (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, honeypot TEXT NOT NULL,
            event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT,
            session_id TEXT NOT NULL, protocol TEXT, service TEXT, destination_port INTEGER,
            country TEXT, asn TEXT, latitude REAL, longitude REAL,
            observed TEXT NOT NULL, enrichment TEXT NOT NULL, derived TEXT NOT NULL,
            hypotheses TEXT NOT NULL, schema_version TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        );
    """)
    timestamp = "2026-08-01T10:00:00+00:00"
    conn.execute(
        "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)",
        ("ses_legacy", "203.0.113.240", "legacy-1", "ssh", "tcp", 22, timestamp, timestamp, 1),
    )
    conn.execute(
        "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "53000000-0000-4000-8000-000000000001", timestamp, "legacy-1", "connection", "info",
            "203.0.113.240", "ses_legacy", "tcp", "ssh", 22, None, None, None, None,
            '{"source_ip":"203.0.113.240","service":"ssh","protocol":"tcp","destination_port":22}',
            "{}", "{}", "[]", "1.1",
        ),
    )
    conn.commit()
    conn.close()

    store = Store(str(path), retention_days=0)
    migrated = store.get_event("53000000-0000-4000-8000-000000000001")
    assert migrated["collector_received_at"] == timestamp
