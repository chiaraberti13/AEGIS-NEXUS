import pytest

from aegis_nexus.model import EventValidationError, normalize_event


def test_credentials_are_redacted_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_STORE_CREDENTIAL_SECRETS", raising=False)
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {"source_ip": "203.0.113.10", "credential": {"username": "root", "password": "toor"}},
    })
    cred = event["observed"]["credential"]
    assert cred["password"] == "[redacted]"
    assert cred["password_length"] == 4
    assert len(cred["password_sha256"]) == 64


def test_invalid_ip_rejected():
    with pytest.raises(EventValidationError):
        normalize_event({"honeypot":"x", "event_type":"connection", "observed":{"source_ip":"not-an-ip"}})


def test_enrichment_requires_provenance():
    with pytest.raises(EventValidationError):
        normalize_event({"honeypot":"x", "event_type":"connection", "enrichment":{"geo":{"data":{"country":"IT"}}}})


def test_mitre_mapping_requires_evidence():
    with pytest.raises(EventValidationError):
        normalize_event({"honeypot":"x", "event_type":"command", "derived":{"mitre":[{"technique_id":"T1059"}]}})


def test_invalid_destination_port_rejected():
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot":"x",
            "event_type":"connection",
            "observed":{"source_ip":"203.0.113.10","destination_port":70000},
        })


def test_ioc_requires_explicit_evidence():
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot":"x",
            "event_type":"web.payload",
            "derived":{"ioc":[{"type":"pattern","value":"example"}]},
        })
