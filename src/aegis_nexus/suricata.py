from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any


class SuricataValidationError(ValueError):
    pass


def _severity(alert: dict[str, Any]) -> str:
    value = alert.get("severity")
    try:
        level = int(value)
    except (TypeError, ValueError):
        return "info"
    if level <= 1:
        return "high"
    if level == 2:
        return "medium"
    if level == 3:
        return "low"
    return "info"


def _stable_event_id(payload: dict[str, Any], sensor_id: str) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aegis:suricata:{sensor_id}:{digest}"))


def normalize_eve_event(payload: dict[str, Any], sensor_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SuricataValidationError("Suricata EVE event must be an object")
    eve_type = str(payload.get("event_type") or "unknown")[:64]
    observed: dict[str, Any] = {
        "source_ip": payload.get("src_ip"),
        "destination_ip": payload.get("dest_ip"),
        "source_port": payload.get("src_port"),
        "destination_port": payload.get("dest_port"),
        "protocol": str(payload.get("proto") or "").lower()[:24],
        "service": str(payload.get("app_proto") or payload.get("proto") or "unknown").lower()[:64],
        "suricata_event_type": eve_type,
    }
    for field in ("flow_id", "community_id", "in_iface"):
        if payload.get(field) not in (None, ""):
            observed[field] = payload[field]
    flow = payload.get("flow")
    if isinstance(flow, dict) and flow.get("start") not in (None, ""):
        observed["flow_start"] = str(flow["start"])[:128]

    event_type = f"suricata.{eve_type}"
    severity = "info"
    if eve_type == "alert":
        alert = payload.get("alert")
        if not isinstance(alert, dict):
            raise SuricataValidationError("Suricata alert event requires alert object")
        event_type = "ids.alert"
        severity = _severity(alert)
        observed["alert"] = {
            key: alert[key]
            for key in ("signature", "signature_id", "category", "action", "severity", "gid", "rev")
            if key in alert
        }

    return {
        "id": _stable_event_id(payload, sensor_id),
        "timestamp": payload.get("timestamp"),
        "honeypot": sensor_id,
        "event_type": event_type,
        "severity": severity,
        "observed": observed,
        "enrichment": {},
        "derived": {},
        "hypotheses": [],
    }
