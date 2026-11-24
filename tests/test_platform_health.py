from __future__ import annotations

import shutil
from pathlib import Path

from aegis_nexus.app import create_app
from aegis_nexus.metrics import render_prometheus
from aegis_nexus.store import Store


def _store(tmp_path):
    return Store(str(tmp_path / "aegis.db"))


def test_operational_health_reports_storage_and_state(tmp_path):
    store = _store(tmp_path)
    health = store.operational_health(min_free_bytes=1)
    assert health["state"] == "healthy"
    assert health["storage"]["event_count"] == 0
    assert health["storage"]["database_size_bytes"] > 0
    assert health["storage"]["max_events"] >= 1000
    assert health["storage"]["retention_days"] >= 0


def test_state_is_critical_when_storage_below_minimum(tmp_path):
    store = _store(tmp_path)
    # Impossible free-space requirement -> storage not ready -> critical.
    health = store.operational_health(min_free_bytes=10 ** 18)
    assert health["storage_ready"] is False
    assert health["state"] == "critical"


def test_state_is_degraded_when_free_space_is_low(tmp_path):
    store = _store(tmp_path)
    free = shutil.disk_usage(Path(store.path).parent).free
    # threshold such that free >= threshold (ready) but free < 2*threshold (low).
    health = store.operational_health(min_free_bytes=max(1, free - 1000))
    assert health["storage_ready"] is True
    assert health["state"] == "degraded"


def test_render_prometheus_emits_fixed_names_and_single_active_state():
    health = {
        "ready": True, "state": "healthy", "database_ready": True,
        "database_schema": {"current": True}, "storage_ready": True,
        "storage_free_bytes": 1000, "min_free_bytes": 10,
        "storage": {"database_size_bytes": 4096, "event_count": 3, "max_events": 1000,
                    "capacity_used_fraction": 0.003, "retention_days": 30},
    }
    telemetry = {"configured_sensors": 2, "configured_with_recent_telemetry": 1,
                 "configured_with_healthy_heartbeat": 1, "sensors_with_sequence_gaps": 0,
                 "missing_sequenced_events": 0}
    text = render_prometheus(health, telemetry)
    assert 'aegis_platform_state{state="healthy"} 1' in text
    assert 'aegis_platform_state{state="critical"} 0' in text
    assert "aegis_events_total 3" in text
    assert "aegis_database_size_bytes 4096" in text
    assert "# TYPE aegis_ready gauge" in text


def test_metrics_endpoint_is_operator_gated_and_prometheus(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    assert client.get("/api/v1/metrics").status_code == 401
    res = client.get("/api/v1/metrics", headers={"X-Aegis-Operator-Key": "operator-secret"})
    assert res.status_code == 200
    assert res.mimetype == "text/plain"
    body = res.get_data(as_text=True)
    assert "aegis_platform_state" in body
    assert "aegis_events_total" in body


def test_operations_status_exposes_platform_state(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    status = client.get("/api/v1/operations/status", headers={"X-Aegis-Operator-Key": "operator-secret"}).get_json()
    assert status["collector"]["state"] in {"healthy", "degraded", "critical"}
    assert "database_size_bytes" in status["collector"]["storage"]
