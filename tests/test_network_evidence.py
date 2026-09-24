import pytest

from aegis_nexus.model import EventValidationError, normalize_event
from aegis_nexus.network_evidence import (
    NETWORK_EVIDENCE_SCHEMA_VERSION,
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
