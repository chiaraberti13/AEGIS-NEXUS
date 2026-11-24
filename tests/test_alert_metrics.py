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


def _make_alert(client):
    client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.70",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "curl http://example.invalid/x",
            },
        },
    )


def test_alert_metrics_require_operator(tmp_path):
    assert _client(tmp_path).get("/api/v1/alerts/metrics").status_code == 401


def test_mtta_mttr_measured_only_after_lifecycle_transitions(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _make_alert(client)
    alert = client.get("/api/v1/alerts", headers=operator).get_json()["items"][0]

    # Fresh alert: counted but no acknowledge/close durations yet.
    metrics = client.get("/api/v1/alerts/metrics", headers=operator).get_json()
    assert metrics["total_alerts"] == 1
    assert metrics["time_to_acknowledge"]["count"] == 0
    assert metrics["time_to_close"]["count"] == 0
    assert "not detector accuracy" in metrics["caveat"]

    # Acknowledge, then close.
    client.patch(f"/api/v1/alerts/{alert['id']}", headers=operator, json={"status": "investigating"})
    client.patch(f"/api/v1/alerts/{alert['id']}", headers=operator, json={"status": "closed"})

    metrics = client.get("/api/v1/alerts/metrics", headers=operator).get_json()
    assert metrics["time_to_acknowledge"]["count"] == 1
    assert metrics["time_to_close"]["count"] == 1
    assert metrics["time_to_acknowledge"]["mean_seconds"] is not None
    assert metrics["time_to_acknowledge"]["mean_seconds"] >= 0
    assert metrics["time_to_close"]["mean_seconds"] >= metrics["time_to_acknowledge"]["mean_seconds"]


def test_acknowledge_timestamp_is_set_once(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _make_alert(client)
    alert_id = client.get("/api/v1/alerts", headers=operator).get_json()["items"][0]["id"]

    first = client.patch(
        f"/api/v1/alerts/{alert_id}", headers=operator, json={"status": "acknowledged"}
    ).get_json()
    # Moving further along the lifecycle must not rewind the acknowledge stamp.
    second = client.patch(
        f"/api/v1/alerts/{alert_id}", headers=operator, json={"status": "investigating"}
    ).get_json()
    assert first["acknowledged_at"]
    assert second["acknowledged_at"] == first["acknowledged_at"]
