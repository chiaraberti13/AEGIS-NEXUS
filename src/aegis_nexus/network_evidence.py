from __future__ import annotations

import math
from datetime import datetime
from typing import Any

NETWORK_EVIDENCE_SCHEMA_VERSION = "1.0"
NETWORK_SOURCES = {"sensor_socket", "http_request", "suricata_eve"}
CAPTURE_LAYERS = {"application", "transport", "ids_flow"}
COMPLETENESS = {"partial", "complete_for_source"}


class NetworkEvidenceValidationError(ValueError):
    pass


def _non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise NetworkEvidenceValidationError(f"{field} must be a non-negative integer")
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise NetworkEvidenceValidationError(f"{field} must be a non-negative integer") from exc
    if numeric < 0:
        raise NetworkEvidenceValidationError(f"{field} must be a non-negative integer")
    return numeric


def _duration_ms(start: Any, end: Any) -> int | None:
    if not start or not end:
        return None
    try:
        start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    value = (end_dt - start_dt).total_seconds() * 1000
    if not math.isfinite(value) or value < 0:
        return None
    return int(round(value))


def make_network_evidence(
    source: str,
    capture_layer: str,
    *,
    completeness: str = "partial",
    transport: dict[str, Any] | None = None,
    connection: dict[str, Any] | None = None,
    http: dict[str, Any] | None = None,
    tls: dict[str, Any] | None = None,
    dns: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": NETWORK_EVIDENCE_SCHEMA_VERSION,
        "source": source,
        "capture_layer": capture_layer,
        "completeness": completeness,
    }
    for key, value in (
        ("transport", transport),
        ("connection", connection),
        ("http", http),
        ("tls", tls),
        ("dns", dns),
    ):
        if isinstance(value, dict) and value:
            evidence[key] = value
    validate_network_evidence(evidence)
    return evidence


def suricata_flow_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    flow = payload.get("flow") if isinstance(payload.get("flow"), dict) else {}
    connection: dict[str, Any] = {}
    mapping = {
        "bytes_toserver": "bytes_to_server",
        "bytes_toclient": "bytes_to_client",
        "pkts_toserver": "packets_to_server",
        "pkts_toclient": "packets_to_client",
    }
    for source_key, target_key in mapping.items():
        if flow.get(source_key) not in (None, ""):
            connection[target_key] = _non_negative_int(flow[source_key], f"flow.{source_key}")
    duration = _duration_ms(flow.get("start"), flow.get("end") or payload.get("timestamp"))
    if duration is not None:
        connection["duration_ms"] = duration

    transport: dict[str, Any] = {}
    if payload.get("src_port") not in (None, ""):
        transport["source_port"] = payload["src_port"]
    if payload.get("dest_port") not in (None, ""):
        transport["destination_port"] = payload["dest_port"]
    if payload.get("proto") not in (None, ""):
        transport["protocol"] = str(payload["proto"]).lower()[:24]
    if payload.get("tcp") and isinstance(payload["tcp"], dict):
        tcp = payload["tcp"]
        flags = tcp.get("tcp_flags") or tcp.get("flags")
        if flags not in (None, ""):
            transport["tcp_flags"] = str(flags)[:64]

    return make_network_evidence(
        "suricata_eve",
        "ids_flow",
        transport=transport,
        connection=connection,
    )


def validate_network_evidence(value: Any) -> None:
    if not isinstance(value, dict):
        raise NetworkEvidenceValidationError("observed.network must be an object")
    if value.get("schema_version") != NETWORK_EVIDENCE_SCHEMA_VERSION:
        raise NetworkEvidenceValidationError("unsupported observed.network schema_version")
    if value.get("source") not in NETWORK_SOURCES:
        raise NetworkEvidenceValidationError("invalid observed.network source")
    if value.get("capture_layer") not in CAPTURE_LAYERS:
        raise NetworkEvidenceValidationError("invalid observed.network capture_layer")
    if value.get("completeness") not in COMPLETENESS:
        raise NetworkEvidenceValidationError("invalid observed.network completeness")

    transport = value.get("transport")
    if transport is not None:
        if not isinstance(transport, dict):
            raise NetworkEvidenceValidationError("observed.network.transport must be an object")
        for field in ("source_port", "destination_port"):
            if transport.get(field) not in (None, ""):
                port = _non_negative_int(transport[field], f"observed.network.transport.{field}")
                if not 1 <= port <= 65535:
                    raise NetworkEvidenceValidationError(f"invalid observed.network.transport.{field}")
                transport[field] = port

    connection = value.get("connection")
    if connection is not None:
        if not isinstance(connection, dict):
            raise NetworkEvidenceValidationError("observed.network.connection must be an object")
        for field in (
            "duration_ms",
            "bytes_in",
            "bytes_out",
            "bytes_to_server",
            "bytes_to_client",
            "packets_in",
            "packets_out",
            "packets_to_server",
            "packets_to_client",
        ):
            if connection.get(field) not in (None, ""):
                connection[field] = _non_negative_int(
                    connection[field],
                    f"observed.network.connection.{field}",
                )

    for field in ("http", "tls", "dns"):
        if value.get(field) is not None and not isinstance(value[field], dict):
            raise NetworkEvidenceValidationError(f"observed.network.{field} must be an object")
