from __future__ import annotations

from aegis_nexus.app import create_app
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def test_sensor_health_flags_silent_and_rates_active(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": "id"},
    })
    store.ingest(event, collector_received_at=event["timestamp"])

    health = store.sensor_health(configured_sensor_ids=["ssh-1", "web-1"], recent_hours=24)
    by_id = {s["sensor_id"]: s for s in health["sensors"]}

    assert by_id["ssh-1"]["health"] == "healthy"
    assert by_id["ssh-1"]["event_rate_per_hour"] > 0
    assert by_id["ssh-1"]["last_event_at"]

    # web-1 is configured but never sent telemetry or a heartbeat -> silent.
    assert by_id["web-1"]["health"] == "silent"
    assert "web-1" in health["silent_sensors"]
    assert health["silent_count"] >= 1


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
        "SENSOR_KEYS": {"ssh-1": "k1", "web-1": "k2"},
    })
    return app.test_client()


def test_sensor_health_endpoint_is_operator_gated(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/v1/sensors/health").status_code == 401
    res = client.get("/api/v1/sensors/health", headers={"X-Aegis-Operator-Key": "operator-secret"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["silent_count"] == 2  # both configured sensors are silent at start
    assert set(body["silent_sensors"]) == {"ssh-1", "web-1"}
    assert "observation" not in body  # summarized away


def test_metrics_include_silent_sensor_gauge(tmp_path):
    client = _client(tmp_path)
    body = client.get("/api/v1/metrics", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_data(as_text=True)
    assert "aegis_sensors_silent 2" in body
