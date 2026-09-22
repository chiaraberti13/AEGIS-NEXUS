import pytest

from aegis_nexus.enrichment import (
    EnrichmentValidationError,
    normalize_manual_enrichment,
    require_global_ip,
)


def test_manual_enrichment_requires_explicit_provenance():
    item = normalize_manual_enrichment({
        "kind": "reputation",
        "source": "fixture-provider",
        "source_reference": "lookup-1",
        "observed_at": "2026-09-22T20:00:00Z",
        "data": {"score": 42, "labels": ["fixture"]},
    })
    assert item["provenance"] == "external_enrichment"
    assert item["source"] == "fixture-provider"


def test_manual_enrichment_rejects_missing_source_and_invalid_timestamp():
    with pytest.raises(EnrichmentValidationError):
        normalize_manual_enrichment({
            "kind": "reputation",
            "observed_at": "2026-09-22T20:00:00Z",
            "data": {},
        })
    with pytest.raises(EnrichmentValidationError):
        normalize_manual_enrichment({
            "kind": "reputation",
            "source": "fixture-provider",
            "observed_at": "not-a-date",
            "data": {},
        })


def test_external_provider_lookup_accepts_only_global_ips():
    assert require_global_ip("8.8.8.8") == "8.8.8.8"
    with pytest.raises(EnrichmentValidationError):
        require_global_ip("127.0.0.1")
    with pytest.raises(EnrichmentValidationError):
        require_global_ip("10.0.0.1")
