from datetime import datetime, timedelta, timezone

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
            "flow_id": 987654,
            "flow": {"start": "2026-09-22T17:59:58Z"},
            "alert":{"signature":"Example IDS signature","signature_id":1001,"severity":1,"category":"Attempted Admin"},
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]
    event = client.get(f"/api/v1/events/{event_id}").get_json()
    assert event["event_type"] == "ids.alert"
    assert event["observed"]["alert"]["signature"] == "Example IDS signature"
    assert event["observed"]["flow_id"] == 987654
    assert event["observed"]["flow_start"] == "2026-09-22T17:59:58Z"
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


def test_csv_exports_neutralize_formula_injection(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    created = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "web-1",
            "event_type": "web.payload",
            "observed": {
                "source_ip": "203.0.113.93",
                "service": "http",
                "protocol": "tcp",
                "destination_port": 80,
                "payload": "=HYPERLINK(\"https://example.invalid\",\"x\")",
            },
        },
    )
    assert created.status_code == 201
    session_id = created.get_json()["session_id"]

    csv_report = client.get(f"/api/v1/reports/session/{session_id}.csv")
    assert csv_report.status_code == 200
    body = csv_report.get_data(as_text=True)
    assert "'=HYPERLINK" in body
    assert ",=HYPERLINK" not in body


def test_per_sensor_allowlist_rejects_cross_sensor_spoofing(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "legacy-shared-key",
        "OPERATOR_API_KEY": "operator-secret",
        "SENSOR_KEYS": {
            "ssh-decoy-01": "ssh-secret",
            "web-decoy-01": "web-secret",
        },
    })
    client = app.test_client()
    payload = {
        "honeypot": "ssh-decoy-01",
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.120",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    }

    accepted = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "ssh-secret", "X-Aegis-Sensor": "ssh-decoy-01"},
        json=payload,
    )
    assert accepted.status_code == 201

    cross_sensor = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "web-secret", "X-Aegis-Sensor": "ssh-decoy-01"},
        json={**payload, "id": "43ba4933-413f-4e2f-8c72-2292a80b63ed"},
    )
    assert cross_sensor.status_code == 401

    shared_fallback = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "legacy-shared-key", "X-Aegis-Sensor": "ssh-decoy-01"},
        json={**payload, "id": "c973fb3e-ddf6-4cf2-b9da-f5b4642c40c5"},
    )
    assert shared_fallback.status_code == 401

    unknown_sensor = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "ssh-secret", "X-Aegis-Sensor": "unknown-decoy"},
        json={
            **payload,
            "id": "1fa10cdc-898d-419c-9803-75e9bda41c73",
            "honeypot": "unknown-decoy",
        },
    )
    assert unknown_sensor.status_code == 401

    public_status = client.get("/api/v1/operator/status").get_json()
    assert public_status["authenticated"] is False
    assert "sensor_auth_mode" not in public_status
    assert "sensor_allowlist_count" not in public_status

    status = client.get(
        "/api/v1/operator/status",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
    ).get_json()
    assert status["authenticated"] is True
    assert status["sensor_auth_mode"] == "per_sensor_allowlist"
    assert status["sensor_allowlist_count"] == 2


def test_json_report_never_exports_opted_in_raw_password(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STORE_CREDENTIAL_SECRETS", "true")
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    created = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "credential",
            "observed": {
                "source_ip": "203.0.113.130",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "credential": {"username": "admin", "password": "raw-opt-in-secret"},
            },
        },
    )
    assert created.status_code == 201
    session_id = created.get_json()["session_id"]

    detail = client.get(f"/api/v1/sessions/{session_id}").get_data(as_text=True)
    assert "raw-opt-in-secret" not in detail
    assert "password_sha256" in detail
    event_id = client.get(f"/api/v1/sessions/{session_id}").get_json()["events"][0]["id"]
    event_detail = client.get(f"/api/v1/events/{event_id}").get_data(as_text=True)
    assert "raw-opt-in-secret" not in event_detail
    assert "password_sha256" in event_detail

    report = client.get(f"/api/v1/reports/session/{session_id}")
    assert report.status_code == 200
    report_text = report.get_data(as_text=True)
    assert "raw-opt-in-secret" not in report_text
    assert "password_sha256" in report_text


def test_exact_asn_and_destination_port_filters(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()

    def ingest(event_id, ip, port, asn):
        return client.post(
            "/api/v1/events",
            headers={"X-Aegis-Key": "secret"},
            json={
                "id": event_id,
                "honeypot": "multi-decoy",
                "event_type": "connection",
                "observed": {
                    "source_ip": ip,
                    "service": "tcp",
                    "protocol": "tcp",
                    "destination_port": port,
                },
                "enrichment": {
                    "asn": {
                        "source": "test-enricher",
                        "observed_at": "2026-09-22T20:00:00Z",
                        "data": {"asn": asn},
                    }
                },
            },
        )

    assert ingest("0188127e-ae4d-4b73-93af-24cedf704f5b", "203.0.113.140", 22, "AS64500").status_code == 201
    assert ingest("aa267aa7-f43e-41b9-a05c-6ac6b7969be4", "203.0.113.141", 80, "AS64501").status_code == 201

    exact = client.get("/api/v1/dashboard?asn=AS64500&destination_port=22&include_simulation=true").get_json()
    assert exact["totals"]["events"] == 1
    assert exact["filters"]["asn"] == "AS64500"
    assert exact["filters"]["destination_port"] == "22"

    no_cross_match = client.get(
        "/api/v1/dashboard?asn=AS64500&destination_port=80&include_simulation=true"
    ).get_json()
    assert no_cross_match["totals"]["events"] == 0

    event_list = client.get("/api/v1/events?asn=AS64501&destination_port=80").get_json()
    assert len(event_list["items"]) == 1
    assert event_list["items"][0]["asn"] == "AS64501"
    assert event_list["items"][0]["destination_port"] == 80

    options = client.get("/api/v1/meta/filters").get_json()
    assert "AS64500" in options["asn"]
    assert "22" in options["destination_port"]


def test_case_delete_requires_closed_status_and_case_capacity_is_bounded(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "MAX_CASES": 1,
    })
    client = app.test_client()

    created = client.post(
        "/api/v1/cases",
        json={"title": "Lifecycle API case", "status": "open", "severity": "low"},
    )
    assert created.status_code == 201
    case_id = created.get_json()["id"]

    capacity = client.post(
        "/api/v1/cases",
        json={"title": "Second case", "status": "open", "severity": "low"},
    )
    assert capacity.status_code == 409
    assert capacity.get_json()["error"] == "case_capacity"

    open_delete = client.delete(f"/api/v1/cases/{case_id}")
    assert open_delete.status_code == 409
    assert open_delete.get_json()["error"] == "case_not_closed"

    closed = client.patch(f"/api/v1/cases/{case_id}", json={"status": "closed"})
    assert closed.status_code == 200

    deleted = client.delete(f"/api/v1/cases/{case_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 404


def test_future_sensor_timestamp_is_rejected_but_historical_import_is_allowed(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "MAX_FUTURE_EVENT_SKEW_SECONDS": 60,
    })
    client = app.test_client()

    future = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    rejected = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "clock-1",
            "event_type": "connection",
            "timestamp": future,
            "observed": {
                "source_ip": "203.0.113.250",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
            },
        },
    )
    assert rejected.status_code == 422
    assert rejected.get_json()["error"] == "clock_validation_error"

    historical = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "clock-2",
            "event_type": "connection",
            "timestamp": "2020-01-01T00:00:00Z",
            "observed": {
                "source_ip": "203.0.113.251",
                "service": "http",
                "protocol": "tcp",
                "destination_port": 80,
            },
        },
    )
    assert historical.status_code == 201
    stored = client.get(f"/api/v1/events/{historical.get_json()['id']}").get_json()
    assert stored["timestamp"].startswith("2020-01-01")
    assert stored["collector_received_at"] != stored["timestamp"]


def test_future_suricata_timestamp_is_rejected(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "MAX_FUTURE_EVENT_SKEW_SECONDS": 30,
    })
    client = app.test_client()
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    response = client.post(
        "/api/v1/integrations/suricata/eve",
        headers={"X-Aegis-Key": "secret", "X-Aegis-Sensor": "suricata-01"},
        json={
            "timestamp": future,
            "event_type": "alert",
            "src_ip": "203.0.113.252",
            "src_port": 40000,
            "dest_ip": "192.0.2.10",
            "dest_port": 22,
            "proto": "TCP",
            "app_proto": "ssh",
            "alert": {"signature": "Clock test", "signature_id": 9001, "severity": 2},
        },
    )
    assert response.status_code == 422
    assert response.get_json()["error"] == "clock_validation_error"
