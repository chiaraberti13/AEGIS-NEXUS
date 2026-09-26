import hashlib
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


def test_lossy_normalization_is_explicitly_disclosed():
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.120",
            "payload": "A" * 5000,
            "unsafe key": "must-not-be-silently-trusted",
        },
    })

    normalization = event["collector"]["normalization"]
    assert len(event["observed"]["payload"]) == 4096
    assert "unsafe key" not in event["observed"]
    assert normalization["lossy"] is True
    assert normalization["truncated"] is True
    assert normalization["counts"]["truncated_strings"] == 1
    assert normalization["counts"]["dropped_keys"] == 1
    assert "observed.payload" in normalization["paths"]["truncated_strings"]
    assert "observed" in normalization["paths"]["dropped_keys"]


def test_credential_fingerprint_uses_original_secret_before_storage_bounds(monkeypatch):
    monkeypatch.delenv("AEGIS_STORE_CREDENTIAL_SECRETS", raising=False)
    secret = "p" * 5000
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.121",
            "credential": {"username": "root", "password": secret},
        },
    })

    credential = event["observed"]["credential"]
    assert credential["password"] == "[redacted]"
    assert credential["password_length"] == len(secret)
    assert credential["password_sha256"] == hashlib.sha256(secret.encode()).hexdigest()
    normalization = event["collector"]["normalization"]
    assert normalization["redacted"] is True
    assert normalization["counts"]["credential_secrets_redacted"] == 1
    assert normalization["lossy"] is False


def test_opted_in_raw_credential_truncation_keeps_original_fingerprint(monkeypatch):
    monkeypatch.setenv("AEGIS_STORE_CREDENTIAL_SECRETS", "true")
    secret = "q" * 5000
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.122",
            "credential": {"username": "root", "password": secret},
        },
    })

    credential = event["observed"]["credential"]
    assert len(credential["password"]) == 4096
    assert credential["password_length"] == len(secret)
    assert credential["password_sha256"] == hashlib.sha256(secret.encode()).hexdigest()
    normalization = event["collector"]["normalization"]
    assert normalization["truncated"] is True
    assert "observed.credential.password" in normalization["paths"]["truncated_strings"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observed", []),
        ("enrichment", []),
        ("derived", []),
        ("hypotheses", {}),
    ],
)
def test_malformed_top_level_event_structures_are_rejected(field, value):
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot": "web-1",
            "event_type": "connection",
            field: value,
        })


def test_sensor_truncated_password_keeps_distinct_fingerprint_provenance(monkeypatch):
    monkeypatch.delenv("AEGIS_STORE_CREDENTIAL_SECRETS", raising=False)
    original = "z" * 5000
    captured = original[:4096]
    original_sha256 = hashlib.sha256(original.encode()).hexdigest()

    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.170",
            "credential": {"username": "root", "password": captured},
            "sensor_capture": {
                "truncated": True,
                "truncated_fields": [{
                    "path": "observed.credential.password",
                    "original_length": len(original),
                    "captured_length": len(captured),
                    "original_sha256": original_sha256,
                }],
            },
        },
    })

    credential = event["observed"]["credential"]
    assert credential["password_complete"] is False
    assert credential["password_length"] == 4096
    assert credential["password_sha256"] == hashlib.sha256(captured.encode()).hexdigest()
    assert credential["sensor_reported_password_length"] == 5000
    assert credential["sensor_reported_password_sha256"] == original_sha256



def test_event_normalization_preserves_canonical_ipv6_source_address():
    event = normalize_event({
        "honeypot": "ssh-decoy-01",
        "event_type": "connection",
        "observed": {
            "source_ip": "2001:0db8:0000:0000:0000:0000:0000:0042",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    })
    assert "source_ip" not in event
    assert event["observed"]["source_ip"] == "2001:db8::42"



def test_event_normalization_collapses_ipv4_mapped_ipv6_to_canonical_ipv4():
    event = normalize_event({
        "honeypot": "web-decoy-01",
        "event_type": "connection",
        "observed": {
            "source_ip": "::ffff:203.0.113.42",
            "destination_ip": "::ffff:192.0.2.20",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 8080,
        },
    })
    assert event["observed"]["source_ip"] == "203.0.113.42"
    assert event["observed"]["destination_ip"] == "192.0.2.20"
