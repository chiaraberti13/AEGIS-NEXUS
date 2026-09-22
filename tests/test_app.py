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


def test_filters_ti_session_study_and_csv_report(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": "secret"})
    client = app.test_client()
    payload = {
        "honeypot": "ssh-decoy-01",
        "event_type": "credential",
        "severity": "medium",
        "observed": {
            "source_ip": "203.0.113.77",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "credential": {"username": "admin", "password": "example-secret"},
        },
        "enrichment": {
            "reputation": {
                "source": "fixture-provider",
                "observed_at": "2026-09-22T18:11:00Z",
                "data": {"score": 42, "classification": "test-only"},
            }
        },
    }
    created = client.post("/api/v1/events", headers={"X-Aegis-Key": "secret"}, json=payload)
    assert created.status_code == 201
    session_id = created.get_json()["session_id"]

    filtered = client.get("/api/v1/dashboard?service=ssh&severity=medium&include_simulation=true").get_json()
    assert filtered["totals"]["events"] == 1
    assert filtered["filters"]["service"] == "ssh"

    no_match = client.get("/api/v1/dashboard?service=http&include_simulation=true").get_json()
    assert no_match["totals"]["events"] == 0

    options = client.get("/api/v1/meta/filters").get_json()
    assert "ssh" in options["service"]
    assert "credential" in options["event_type"]

    ti = client.get("/api/v1/ips/203.0.113.77/threat-intelligence").get_json()
    assert ti["items"][0]["source"] == "fixture-provider"
    assert ti["items"][0]["provenance"] == "external_enrichment"

    study = client.get(f"/api/v1/study/session/{session_id}?lang=it").get_json()
    assert study["facts"]
    assert study["next_steps"]

    csv_report = client.get(f"/api/v1/reports/session/{session_id}.csv")
    assert csv_report.status_code == 200
    assert csv_report.mimetype == "text/csv"
    body = csv_report.get_data(as_text=True)
    assert "admin" in body
    assert "example-secret" not in body


def test_frontend_shell_exposes_soc_workspace(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db"), "INGEST_API_KEY": "secret"})
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    for marker in (
        'data-view="dashboard"',
        'data-view="investigate"',
        'data-view="relations"',
        'data-view="study"',
        'id="map-zoom-in"',
        'id="event-feed"',
        'id="ti-list"',
        'id="relation-graph"',
        'id="session-study"',
    ):
        assert marker in html


def test_case_api_is_operator_protected_and_exports_reference_only(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    created_event = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-decoy-01",
            "event_type": "credential",
            "observed": {
                "source_ip": "203.0.113.92",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "credential": {"username": "root", "password": "do-not-export"},
            },
        },
    )
    assert created_event.status_code == 201
    event_id = created_event.get_json()["id"]

    assert client.get("/api/v1/cases").status_code == 401
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    case_response = client.post(
        "/api/v1/cases",
        headers=operator,
        json={"title": "Credential investigation", "severity": "medium", "tags": ["ssh", "credential"]},
    )
    assert case_response.status_code == 201
    case_id = case_response.get_json()["id"]

    evidence = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=operator,
        json={"type": "event", "id": event_id},
    )
    assert evidence.status_code == 200

    note = client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=operator,
        json={"body": "Analyst note: compare reuse across sessions."},
    )
    assert note.status_code == 201

    report = client.get(f"/api/v1/reports/case/{case_id}", headers=operator)
    assert report.status_code == 200
    report_text = report.get_data(as_text=True)
    assert "do-not-export" not in report_text
    assert '"classification_provenance":"analyst"' in report_text

    csv_report = client.get(f"/api/v1/reports/case/{case_id}.csv", headers=operator)
    assert csv_report.status_code == 200
    assert event_id in csv_report.get_data(as_text=True)
    assert "do-not-export" not in csv_report.get_data(as_text=True)


def test_operator_triggered_abuseipdb_enrichment_is_cached_and_provenance_safe(tmp_path, monkeypatch):
    calls = []

    def fake_lookup(ip, api_key, *, max_age_days, timeout):
        calls.append((ip, api_key, max_age_days, timeout))
        return {
            "kind": "reputation",
            "source": "AbuseIPDB API v2",
            "source_reference": "check",
            "observed_at": "2026-09-22T20:30:00+00:00",
            "data": {
                "ipAddress": ip,
                "abuseConfidenceScore": 73,
                "totalReports": 12,
            },
            "provenance": "external_enrichment",
        }

    monkeypatch.setattr("aegis_nexus.app.enrichment_module.fetch_abuseipdb", fake_lookup)
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
        "ABUSEIPDB_API_KEY": "provider-secret",
        "ABUSEIPDB_MAX_AGE_DAYS": 30,
        "ENRICHMENT_CACHE_HOURS": 6,
        "ENRICHMENT_TIMEOUT": 2.0,
    })
    client = app.test_client()
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    providers = client.get("/api/v1/enrichment/providers", headers=operator).get_json()
    assert providers["abuseipdb"]["configured"] is True
    assert providers["abuseipdb"]["automatic"] is False

    first = client.post(
        "/api/v1/enrichment/ip/8.8.8.8/abuseipdb",
        headers=operator,
        json={"force": False},
    )
    assert first.status_code == 201
    assert first.get_json()["cached"] is False

    second = client.post(
        "/api/v1/enrichment/ip/8.8.8.8/abuseipdb",
        headers=operator,
        json={"force": False},
    )
    assert second.status_code == 200
    assert second.get_json()["cached"] is True
    assert len(calls) == 1

    ti = client.get("/api/v1/ips/8.8.8.8/threat-intelligence", headers=operator).get_json()
    assert ti["items"][0]["source"] == "AbuseIPDB API v2"
    assert ti["items"][0]["provenance"] == "external_enrichment"
    assert ti["items"][0]["record_origin"] == "standalone_enrichment"
    assert ti["items"][0]["data"]["abuseConfidenceScore"] == 73


def test_manual_external_enrichment_stays_separate_from_observed_events(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    response = client.post(
        "/api/v1/enrichment/ip/203.0.113.55",
        headers=operator,
        json={
            "kind": "asn_context",
            "source": "fixture-provider",
            "source_reference": "fixture-1",
            "observed_at": "2026-09-22T20:00:00Z",
            "data": {"asn": "AS64500", "note": "test only"},
        },
    )
    assert response.status_code == 201

    profile = client.get("/api/v1/ips/203.0.113.55", headers=operator).get_json()
    assert profile["event_count"] == 0
    assert profile["events"] == []
    assert profile["threat_intelligence"][0]["source"] == "fixture-provider"
    assert profile["threat_intelligence"][0]["record_origin"] == "standalone_enrichment"
