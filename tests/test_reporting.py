from aegis_nexus.app import create_app
from aegis_nexus.reporting import MAX_MARKDOWN_EVENTS, session_markdown


def test_session_markdown_redacts_raw_password_and_escapes_hostile_markup(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STORE_CREDENTIAL_SECRETS", "true")
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    common_observed = {
        "source_ip": "203.0.113.210",
        "service": "http",
        "protocol": "tcp",
        "destination_port": 80,
        "sensor_session_id": "markdown-session",
    }
    credential = {
        "id": "30000000-0000-4000-8000-000000000001",
        "timestamp": "2026-09-22T20:00:00Z",
        "honeypot": "web-1",
        "event_type": "credential",
        "severity": "medium",
        "observed": {
            **common_observed,
            "credential": {"username": "admin", "password": "markdown-raw-secret"},
        },
    }
    payload = {
        "id": "30000000-0000-4000-8000-000000000002",
        "timestamp": "2026-09-22T20:01:00Z",
        "honeypot": "web-1",
        "event_type": "web.payload",
        "severity": "medium",
        "observed": {
            **common_observed,
            "payload": "<script>alert(1)</script>\\n# heading\\n```html\\n<img src=x onerror=alert(2)>\\n```",
        },
    }
    first = client.post("/api/v1/events", headers={"X-Aegis-Key": "secret"}, json=credential)
    second = client.post("/api/v1/events", headers={"X-Aegis-Key": "secret"}, json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    session_id = first.get_json()["session_id"]
    assert second.get_json()["session_id"] == session_id

    response = client.get(f"/api/v1/reports/session/{session_id}.md?lang=it")
    assert response.status_code == 200
    assert response.content_type.startswith("text/markdown")
    body = response.get_data(as_text=True)

    assert "Report investigativo di sessione" in body
    assert "markdown-raw-secret" not in body
    assert "SHA-256 password" in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "&lt;img src=x onerror=alert(2)&gt;" in body
    assert "<script>" not in body


def test_case_markdown_escapes_analyst_markup_and_keeps_reference_only_evidence(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    event = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.211",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "echo source-telemetry-secret",
            },
        },
    )
    assert event.status_code == 201
    event_id = event.get_json()["id"]
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    case = client.post(
        "/api/v1/cases",
        headers=operator,
        json={
            "title": "<img src=x onerror=alert(1)>",
            "summary": "# analyst heading <script>alert(2)</script>",
            "severity": "medium",
            "tags": ["triage", "<b>tag</b>"],
        },
    )
    assert case.status_code == 201
    case_id = case.get_json()["id"]
    assert client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=operator,
        json={"type": "event", "id": event_id},
    ).status_code == 200
    assert client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=operator,
        json={"body": "*note* <script>alert(3)</script>"},
    ).status_code == 201

    response = client.get(f"/api/v1/reports/case/{case_id}.md?lang=en", headers=operator)
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert "Case report" in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in body
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in body
    assert "<script>" not in body
    assert event_id in body
    assert "source-telemetry-secret" not in body


def test_session_markdown_event_appendix_is_bounded():
    events = []
    for index in range(MAX_MARKDOWN_EVENTS + 5):
        events.append({
            "id": f"evt-{index}",
            "timestamp": "2026-09-22T20:00:00+00:00",
            "event_type": "connection",
            "severity": "info",
            "source_ip": "203.0.113.1",
            "observed": {"source_ip": "203.0.113.1"},
            "enrichment": {},
            "derived": {},
            "hypotheses": [],
        })
    report = {
        "report_type": "investigation_session",
        "generated_at": "2026-09-22T21:00:00+00:00",
        "session": {"id": "ses_test"},
        "summary": {},
        "facts": {"event_count": len(events)},
        "credentials": [],
        "commands": [],
        "payloads": [],
        "enrichment": [],
        "derived_iocs": [],
        "evidence_backed_mappings": [],
        "events": events,
        "limitations": [],
    }
    body = session_markdown(report, "en")
    assert f"evt-{MAX_MARKDOWN_EVENTS - 1}" in body
    assert f"evt-{MAX_MARKDOWN_EVENTS}" not in body
    assert f"Appendix limited to the first {MAX_MARKDOWN_EVENTS}" in body


def test_frontend_exposes_markdown_report_controls(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'id="report-markdown"' in html
    assert 'id="case-report-markdown"' in html
