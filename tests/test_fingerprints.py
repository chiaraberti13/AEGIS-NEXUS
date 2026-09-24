import pytest

from aegis_nexus.fingerprints import (
    FingerprintFinding,
    NullPassiveFingerprintProvider,
)


def test_passive_fingerprint_finding_requires_evidence_and_never_attributes():
    finding = FingerprintFinding(
        provider="fixture-passive",
        kind="tls_client",
        fingerprint="ja3:0123456789abcdef",
        evidence=("observed.network.tls.ja3.hash",),
        confidence=0.8,
        label="fixture client fingerprint",
    ).as_dict()
    assert finding["provider"] == "fixture-passive"
    assert finding["evidence"] == ["observed.network.tls.ja3.hash"]
    assert finding["confidence"] == 0.8
    assert finding["attribution"] is False


def test_passive_fingerprint_interface_rejects_direct_os_claim_kind():
    with pytest.raises(ValueError):
        FingerprintFinding(
            provider="fixture-passive",
            kind="operating_system",
            fingerprint="unsupported-os-claim",
            evidence=("observed.network.transport.tcp_flags",),
        ).as_dict()


def test_null_passive_fingerprint_provider_is_safe_default():
    provider = NullPassiveFingerprintProvider()
    assert provider.name == "disabled"
    assert provider.analyze({"schema_version": "1.0"}) == ()
