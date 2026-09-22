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
