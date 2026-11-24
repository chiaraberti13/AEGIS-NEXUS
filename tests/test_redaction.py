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
