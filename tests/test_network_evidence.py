import pytest

from aegis_nexus.model import EventValidationError, normalize_event
from aegis_nexus.network_evidence import (
    NETWORK_EVIDENCE_SCHEMA_VERSION,
    NetworkEvidenceValidationError,
    make_network_evidence,
    suricata_flow_evidence,
)


def test_network_evidence_schema_preserves_source_and_capture_layer():
    network = make_network_evidence(
        "sensor_socket",
        "application",
        transport={"protocol": "tcp", "source_port": 45000, "destination_port": 22},
        connection={"duration_ms": 1250, "bytes_in": 42, "bytes_out": 18},
    )
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "connection.closed",
        "observed": {
            "source_ip": "203.0.113.10",
            "network": network,
        },
    })
    stored = event["observed"]["network"]
    assert stored["schema_version"] == NETWORK_EVIDENCE_SCHEMA_VERSION
    assert stored["source"] == "sensor_socket"
    assert stored["capture_layer"] == "application"
    assert stored["completeness"] == "partial"
    assert stored["connection"]["duration_ms"] == 1250


@pytest.mark.parametrize(
    "network",
    [
        {"schema_version": "999", "source": "sensor_socket", "capture_layer": "application", "completeness": "partial"},
        {"schema_version": "1.0", "source": "invented", "capture_layer": "application", "completeness": "partial"},
        {"schema_version": "1.0", "source": "sensor_socket", "capture_layer": "kernel_magic", "completeness": "partial"},
        {"schema_version": "1.0", "source": "sensor_socket", "capture_layer": "application", "completeness": "partial", "connection": {"bytes_in": -1}},
        {"schema_version": "1.0", "source": "sensor_socket", "capture_layer": "application", "completeness": "partial", "transport": {"source_port": 70000}},
    ],
)
def test_network_evidence_rejects_unsupported_or_impossible_claims(network):
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot": "sensor-1",
            "event_type": "connection",
            "observed": {"source_ip": "203.0.113.11", "network": network},
        })


def test_suricata_flow_evidence_captures_available_counters_and_duration():
    network = suricata_flow_evidence({
        "timestamp": "2026-09-24T09:00:02Z",
        "src_port": 50123,
        "dest_port": 22,
        "proto": "TCP",
        "flow": {
            "start": "2026-09-24T09:00:00Z",
            "end": "2026-09-24T09:00:02Z",
            "bytes_toserver": 120,
            "bytes_toclient": 340,
            "pkts_toserver": 3,
            "pkts_toclient": 4,
        },
    })
    assert network["source"] == "suricata_eve"
    assert network["capture_layer"] == "ids_flow"
    assert network["connection"] == {
        "bytes_to_server": 120,
        "bytes_to_client": 340,
        "packets_to_server": 3,
        "packets_to_client": 4,
        "duration_ms": 2000,
    }
    assert network["transport"]["source_port"] == 50123
    assert network["transport"]["destination_port"] == 22
    assert network["transport"]["protocol"] == "tcp"


def test_ssh_hassh_and_offer_lists_pass_validation_and_normalization():
    network = make_network_evidence(
        "sensor_socket",
        "application",
        transport={"protocol": "tcp", "destination_port": 22},
        ssh={
            "client_version": "SSH-2.0-OpenSSH_9.6p1",
            "kex_algorithms": ["curve25519-sha256"],
            "encryption_algorithms": ["aes128-ctr"],
            "mac_algorithms": ["hmac-sha2-256"],
            "compression_algorithms": ["none"],
            "hassh": "e97d07603350d1111ec2b64bf25413c9",
            "hassh_algorithms": "curve25519-sha256;aes128-ctr;hmac-sha2-256;none",
        },
    )
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "connection.identified",
        "severity": "info",
        "observed": {"source_ip": "203.0.113.70", "network": network},
    })
    assert event["observed"]["network"]["ssh"]["hassh"] == "e97d07603350d1111ec2b64bf25413c9"


def test_ssh_hassh_must_be_32_hex_digest():
    # The collector fails closed on a malformed fingerprint rather than storing it.
    with pytest.raises(NetworkEvidenceValidationError):
        make_network_evidence(
            "sensor_socket", "application",
            ssh={"hassh": "not-a-valid-hassh"},
        )


def test_ssh_offer_list_rejects_overlong_algorithm_name():
    with pytest.raises(NetworkEvidenceValidationError):
        make_network_evidence(
            "sensor_socket", "application",
            ssh={"kex_algorithms": ["x" * 65]},
        )


def test_ssh_offer_list_rejects_too_many_algorithms():
    from aegis_nexus.network_evidence import MAX_SSH_ALGORITHMS

    with pytest.raises(NetworkEvidenceValidationError):
        make_network_evidence(
            "sensor_socket", "application",
            ssh={"kex_algorithms": [f"k{i}" for i in range(MAX_SSH_ALGORITHMS + 1)]},
        )


def test_collector_rejects_ssh_algorithm_name_over_cap_from_a_payload():
    # Independent collector-side enforcement: even if a sensor were compromised
    # and sent an over-long algorithm name, normalize_event refuses it
    # (fail-closed) — the name exceeds the SSH cap but not the generic string
    # cap, so it reaches validate_network_evidence and raises.
    forged = {
        "schema_version": NETWORK_EVIDENCE_SCHEMA_VERSION,
        "source": "sensor_socket",
        "capture_layer": "application",
        "completeness": "partial",
        "ssh": {"kex_algorithms": ["x" * 65]},
    }
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot": "ssh-1",
            "event_type": "connection.identified",
            "severity": "info",
            "observed": {"source_ip": "203.0.113.71", "network": forged},
        })


def test_collector_bounds_oversize_ssh_offer_list_and_discloses():
    # A too-long offer list is bounded (to the collector's generic item cap) and
    # the loss is disclosed under collector.normalization — truncate-and-disclose,
    # never silent, never a stored over-cap list.
    from aegis_nexus.network_evidence import MAX_SSH_ALGORITHMS

    forged = {
        "schema_version": NETWORK_EVIDENCE_SCHEMA_VERSION,
        "source": "sensor_socket",
        "capture_layer": "application",
        "completeness": "partial",
        "ssh": {"kex_algorithms": [f"k{i}" for i in range(MAX_SSH_ALGORITHMS + 5)]},
    }
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "connection.identified",
        "severity": "info",
        "observed": {"source_ip": "203.0.113.72", "network": forged},
    })
    stored = event["observed"]["network"]["ssh"]["kex_algorithms"]
    assert len(stored) <= MAX_SSH_ALGORITHMS
    normalization = event["collector"]["normalization"]
    assert normalization["lossy"] is True
    assert "observed.network.ssh.kex_algorithms" in normalization["paths"]["truncated_collections"]


def test_suricata_ja4h_http_fingerprint_is_passed_through_as_observed_evidence():
    # JA4H computed by an external IDS (Suricata/Zeek) is preserved as observed
    # passthrough evidence — AEGIS never computes the FoxIO JA4+ methods itself
    # (ADR 0005). Mirrors the existing ja3/ja4 TLS passthrough.
    from aegis_nexus.suricata import normalize_eve_event

    # (a) ja4h as a bare string inside the http object
    event = normalize_event(normalize_eve_event({
        "timestamp": "2026-09-22T18:05:00Z",
        "event_type": "http",
        "src_ip": "203.0.113.9", "src_port": 51111,
        "dest_ip": "192.0.2.10", "dest_port": 80, "proto": "TCP",
        "http": {"hostname": "portal.example.invalid", "http_method": "GET",
                 "ja4h": "ge11nn09enus_fixturehash"},
    }, "suricata-01"))
    assert event["observed"]["network"]["http"]["ja4h"] == "ge11nn09enus_fixturehash"
    # It is observed evidence, never promoted to a derived/enrichment verdict.
    assert event["derived"] == {}

    # (b) ja4h as a {hash,string} object
    event2 = normalize_event(normalize_eve_event({
        "timestamp": "2026-09-22T18:06:00Z",
        "event_type": "http",
        "src_ip": "203.0.113.9", "src_port": 51112,
        "dest_ip": "192.0.2.10", "dest_port": 80, "proto": "TCP",
        "http": {"hostname": "portal.example.invalid",
                 "ja4h": {"hash": "ge11nn09enus_h", "string": "ge11nn09enus_raw"}},
    }, "suricata-01"))
    assert event2["observed"]["network"]["http"]["ja4h"]["hash"] == "ge11nn09enus_h"

    # (c) ja4h at the record top level (some producers emit it there)
    event3 = normalize_event(normalize_eve_event({
        "timestamp": "2026-09-22T18:07:00Z",
        "event_type": "http",
        "src_ip": "203.0.113.9", "src_port": 51113,
        "dest_ip": "192.0.2.10", "dest_port": 80, "proto": "TCP",
        "http": {"hostname": "portal.example.invalid"},
        "ja4h": "ge11nn09enus_toplevel",
    }, "suricata-01"))
    assert event3["observed"]["network"]["http"]["ja4h"] == "ge11nn09enus_toplevel"
