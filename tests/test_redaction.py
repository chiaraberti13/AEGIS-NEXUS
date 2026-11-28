from __future__ import annotations

import json

from aegis_nexus.app import create_app
from aegis_nexus.redaction import mask_ip, redact_report


def test_mask_ip_keeps_only_network_prefix():
    assert mask_ip("203.0.113.40") == "203.0.113.0/24"
    assert mask_ip("2001:db8::1") == "2001:db8::/48"
    assert mask_ip("not-an-ip") == "[redacted-ip]"


def test_shareable_redacts_structured_identifiers_recursively():
    report = {
        "session": {"source_ip": "203.0.113.40"},
        "credentials": [{"username": "root", "password_sha256": "abc"}],
        "owner": "analyst-1",
        "operator_audit": [{"operator": "analyst-2", "source_ip": "198.51.100.7", "action": "case.update"}],
        "events": [{"source_ip": "203.0.113.41"}],
    }
    internal = redact_report(report, "internal")
    assert internal["session"]["source_ip"] == "203.0.113.40"
    assert internal["redaction_profile"] == "internal"

    shareable = redact_report(report, "shareable")
    assert shareable["session"]["source_ip"] == "203.0.113.0/24"
    assert shareable["events"][0]["source_ip"] == "203.0.113.0/24"
    assert shareable["credentials"][0]["username"] == "[redacted-username]"
    assert shareable["credentials"][0]["password_sha256"] == "abc"  # fingerprint kept
    assert shareable["owner"] == "[redacted-operator]"
    assert shareable["operator_audit"][0]["operator"] == "[redacted-operator]"
    assert shareable["operator_audit"][0]["source_ip"] == "198.51.100.0/24"
    assert "not full" in shareable["redaction_note"]
    # The original report is not mutated.
    assert report["session"]["source_ip"] == "203.0.113.40"


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
    })
    return app.test_client()


def test_session_report_shareable_profile_masks_pii(tmp_path):
    client = _client(tmp_path)
    session_id = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "auth_attempt",
            "observed": {
                "source_ip": "203.0.113.40",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "credential": {"username": "root", "password": "hunter2"},
            },
        },
    ).get_json()["session_id"]

    internal = client.get(f"/api/v1/reports/session/{session_id}").get_json()
    assert "203.0.113.40" in json.dumps(internal)

    shareable = client.get(f"/api/v1/reports/session/{session_id}?profile=shareable").get_json()
    blob = json.dumps(shareable)
    assert "203.0.113.40" not in blob  # raw attacker IP never leaks
    assert "203.0.113.0/24" in blob
    assert "root" not in blob  # username removed
    assert shareable["redaction_profile"] == "shareable"


def test_shareable_markdown_carries_redaction_banner(tmp_path):
    client = _client(tmp_path)
    session_id = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "auth_attempt",
            "observed": {"source_ip": "203.0.113.40", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "credential": {"username": "admin", "password": "x"}},
        },
    ).get_json()["session_id"]

    body = client.get(f"/api/v1/reports/session/{session_id}.md?profile=shareable&lang=en").get_data(as_text=True)
    assert "Redaction: shareable" in body
    assert "203.0.113.40" not in body


def test_reports_reject_ambiguous_or_unsupported_privacy_profiles(tmp_path):
    client = _client(tmp_path)
    for resource in ("case/example", "session/example"):
        for extension in ("", ".md", ".pdf"):
            for query in ("profile=unknown", "profile=", "profile=internal&profile=shareable"):
                response = client.get(f"/api/v1/reports/{resource}{extension}?{query}")
                assert response.status_code == 400
                assert response.get_json() == {"error": "invalid_report_profile"}

    for path in ("case/example/bundle.zip", "case/example.csv", "session/example.csv",
                 "soc-summary", "soc-summary.md"):
        response = client.get(f"/api/v1/reports/{path}?profile=shareable")
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_report_profile"}


def test_shareable_exports_localize_privacy_notice(tmp_path):
    client = _client(tmp_path)
    case = client.post("/api/v1/cases", json={"title": "Research case"}).get_json()
    url = f"/api/v1/reports/case/{case['id']}"
    json_report = client.get(f"{url}?profile=shareable&lang=it").get_json()
    assert "L'anonimizzazione è parziale" in json_report["redaction_note"]
    markdown = client.get(f"{url}.md?profile=shareable&lang=it").get_data(as_text=True)
    assert "Profilo di condivisione" in markdown
    assert json_report["redaction_note"] in markdown
    pdf = client.get(f"{url}.pdf?profile=shareable&lang=it")
    assert pdf.status_code == 200
    assert b"Profilo di condivisione" in pdf.data
