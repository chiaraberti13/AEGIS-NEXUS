from aegis_nexus.app import create_app


def test_ingest_and_dashboard(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": "secret"})
    client = app.test_client()
    denied = client.post("/api/v1/events", json={"honeypot":"web","event_type":"connection"})
    assert denied.status_code == 401
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key":"secret"},
        json={"honeypot":"web","event_type":"connection","observed":{"source_ip":"203.0.113.4","service":"http","protocol":"tcp","destination_port":80}},
    )
    assert response.status_code == 201
    dashboard = client.get("/api/v1/dashboard?include_simulation=true").get_json()
    assert dashboard["totals"]["events"] == 1
    assert dashboard["totals"]["unique_source_ip"] == 1


def test_ingest_fails_closed_without_key(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": ""})
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        json={"honeypot":"web","event_type":"connection","observed":{"source_ip":"203.0.113.5"}},
    )
    assert response.status_code == 401


def test_sensor_identity_must_match_payload(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": "secret"})
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key":"secret","X-Aegis-Sensor":"ssh-decoy-01"},
        json={"honeypot":"web-decoy-01","event_type":"connection","observed":{"source_ip":"203.0.113.6"}},
    )
    assert response.status_code == 401


def test_suricata_alert_ingestion_preserves_evidence_without_inventing_mappings(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": "secret"})
    client = app.test_client()
    response = client.post(
        "/api/v1/integrations/suricata/eve",
        headers={"X-Aegis-Key":"secret","X-Aegis-Sensor":"suricata-01"},
        json={
            "timestamp":"2026-09-22T18:00:00Z",
            "event_type":"alert",
            "src_ip":"203.0.113.8",
            "src_port":44444,
            "dest_ip":"192.0.2.10",
            "dest_port":22,
            "proto":"TCP",
            "app_proto":"ssh",
            "alert":{"signature":"Example IDS signature","signature_id":1001,"severity":1,"category":"Attempted Admin"},
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]
    event = client.get(f"/api/v1/events/{event_id}").get_json()
    assert event["event_type"] == "ids.alert"
    assert event["observed"]["alert"]["signature"] == "Example IDS signature"
    assert event["derived"] == {}
