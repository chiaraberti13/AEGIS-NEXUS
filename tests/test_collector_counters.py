from __future__ import annotations

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.store import Store

_EVENT = {
    "honeypot": "ssh-1",
    "event_type": "command",
    "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                 "destination_port": 22, "command": "id"},
}


def test_store_counter_increment_and_allowlist(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    assert store.counters()["sensor_auth_failures"] == 0
    store.increment_counter("sensor_auth_failures")
    store.increment_counter("sensor_auth_failures")
    assert store.counters()["sensor_auth_failures"] == 2
    with pytest.raises(ValueError):
        store.increment_counter("not_a_real_counter")


def _app(tmp_path, **extra):
    cfg = {
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    }
    cfg.update(extra)
    return create_app(cfg)


def test_auth_failure_is_counted(tmp_path):
    client = _app(tmp_path).test_client()
    bad = client.post("/api/v1/events", headers={"X-Aegis-Key": "wrong"}, json=_EVENT)
    assert bad.status_code == 401
    status = client.get("/api/v1/operations/status", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_json()
    assert status["counters"]["sensor_auth_failures"] >= 1


def test_validation_rejection_is_counted(tmp_path):
    client = _app(tmp_path).test_client()
    future = {**_EVENT, "timestamp": "2100-01-01T00:00:00Z"}
    rej = client.post("/api/v1/events", headers={"X-Aegis-Key": "sensor-secret"}, json=future)
    assert rej.status_code == 422
    body = client.get("/api/v1/metrics", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_data(as_text=True)
    assert "aegis_ingest_validation_rejections_total" in body


def test_load_shedding_rejects_and_counts_when_disk_is_low(tmp_path):
    # Impossible free-space requirement -> every ingest is shed as evidence loss.
    client = _app(tmp_path, MIN_FREE_BYTES=10 ** 18).test_client()
    shed = client.post("/api/v1/events", headers={"X-Aegis-Key": "sensor-secret"}, json=_EVENT)
    assert shed.status_code == 503
    assert shed.get_json()["error"] == "load_shed"
    status = client.get("/api/v1/operations/status", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_json()
    assert status["counters"]["load_shed_events"] >= 1


def test_metrics_expose_counters_as_counter_type(tmp_path):
    client = _app(tmp_path).test_client()
    client.post("/api/v1/events", headers={"X-Aegis-Key": "wrong"}, json=_EVENT)  # one auth failure
    body = client.get("/api/v1/metrics", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_data(as_text=True)
    assert "# TYPE aegis_sensor_auth_failures_total counter" in body
    assert "aegis_sensor_auth_failures_total 1" in body
