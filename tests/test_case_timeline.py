from __future__ import annotations

from aegis_nexus.app import create_app


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    return app.test_client()


def test_case_timeline_requires_operator_and_404s_unknown(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/v1/cases/case_x/timeline").status_code == 401
    missing = client.get("/api/v1/cases/case_x/timeline", headers={"X-Aegis-Operator-Key": "operator-secret"})
    assert missing.status_code == 404


def test_timeline_merges_observed_evidence_and_analyst_actions_in_order(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    # Event observed well in the past, so it must sort before the (now) case actions.
    event_id = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "timestamp": "2026-11-01T00:00:00Z",
            "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": "id"},
        },
    ).get_json()["id"]
    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "Timeline case"}).get_json()["id"]
    client.post(f"/api/v1/cases/{case_id}/evidence", headers=operator, json={"type": "event", "id": event_id})
    client.post(f"/api/v1/cases/{case_id}/notes", headers=operator, json={"body": "Triaging."})

    timeline = client.get(f"/api/v1/cases/{case_id}/timeline", headers=operator).get_json()
    kinds = [e["kind"] for e in timeline["entries"]]
    assert "case.created" in kinds
    assert "evidence.linked" in kinds
    assert "evidence.observed" in kinds
    assert "note.added" in kinds

    observed = [e for e in timeline["entries"] if e["kind"] == "evidence.observed"]
    assert observed and observed[0]["provenance"] == "observed"
    assert observed[0]["timestamp"].startswith("2026-11-01")
    # The observed (past) evidence sorts first; provenance classes stay labelled.
    assert timeline["entries"][0]["kind"] == "evidence.observed"
    assert {e["provenance"] for e in timeline["entries"]} <= {"observed", "analyst", "collector"}
    timestamps = [e["timestamp"] for e in timeline["entries"]]
    assert timestamps == sorted(timestamps)
    assert "re-derived" in timeline["provenance_note"]
