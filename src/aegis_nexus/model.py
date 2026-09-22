from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
MAX_STRING = 4096
MAX_ITEMS = 128
MAX_DEPTH = 6
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")


class EventValidationError(ValueError):
    pass


def _utc_iso(value: Any | None = None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str):
        raise EventValidationError("timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventValidationError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise EventValidationError("payload nesting too deep")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_STRING]
    if isinstance(value, list):
        return [_bounded(v, depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in list(value.items())[:MAX_ITEMS]:
            key = str(raw_key)
            if not _SAFE_KEY.fullmatch(key):
                continue
            clean[key] = _bounded(raw_value, depth + 1)
        return clean
    return str(value)[:MAX_STRING]


def _normalize_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise EventValidationError("invalid source_ip") from exc


def _redact_credentials(observed: dict[str, Any]) -> dict[str, Any]:
    observed = deepcopy(observed)
    credential = observed.get("credential")
    if not isinstance(credential, dict):
        return observed
    password = credential.get("password")
    if password is None:
        return observed
    password_text = str(password)
    credential["password_length"] = len(password_text)
    credential["password_sha256"] = hashlib.sha256(password_text.encode("utf-8", "replace")).hexdigest()
    if os.getenv("AEGIS_STORE_CREDENTIAL_SECRETS", "false").lower() not in {"1", "true", "yes"}:
        credential["password"] = "[redacted]"
    return observed


def _validate_evidence_mappings(derived: dict[str, Any]) -> None:
    for key in ("mitre", "cve"):
        entries = derived.get(key, [])
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise EventValidationError(f"derived.{key} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise EventValidationError(f"derived.{key} entries must be objects")
            if not entry.get("rationale") or not entry.get("evidence"):
                raise EventValidationError(f"derived.{key} requires rationale and evidence")


def _validate_enrichment(enrichment: dict[str, Any]) -> None:
    for key, value in enrichment.items():
        if not isinstance(value, dict):
            raise EventValidationError(f"enrichment.{key} must be an object")
        if not value.get("source") or not value.get("observed_at"):
            raise EventValidationError(f"enrichment.{key} requires source and observed_at")


def normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EventValidationError("event must be a JSON object")
    observed = _bounded(payload.get("observed") or {})
    enrichment = _bounded(payload.get("enrichment") or {})
    derived = _bounded(payload.get("derived") or {})
    hypotheses = _bounded(payload.get("hypotheses") or [])
    if not isinstance(observed, dict) or not isinstance(enrichment, dict) or not isinstance(derived, dict):
        raise EventValidationError("observed, enrichment and derived must be objects")
    if not isinstance(hypotheses, list):
        raise EventValidationError("hypotheses must be a list")
    _validate_enrichment(enrichment)
    _validate_evidence_mappings(derived)
    observed = _redact_credentials(observed)
    severity = str(payload.get("severity", "info")).lower()
    if severity not in _ALLOWED_SEVERITIES:
        raise EventValidationError("invalid severity")
    honeypot = str(payload.get("honeypot", "unknown"))[:96]
    event_type = str(payload.get("event_type", "unknown"))[:96]
    if not _SAFE_KEY.fullmatch(honeypot) or not _SAFE_KEY.fullmatch(event_type):
        raise EventValidationError("invalid honeypot or event_type")
    source_ip = _normalize_ip(observed.get("source_ip"))
    if source_ip:
        observed["source_ip"] = source_ip
    event_id = str(payload.get("id") or uuid.uuid4())
    try:
        uuid.UUID(event_id)
    except ValueError as exc:
        raise EventValidationError("id must be a UUID") from exc
    return {
        "schema_version": SCHEMA_VERSION,
        "id": event_id,
        "timestamp": _utc_iso(payload.get("timestamp")),
        "honeypot": honeypot,
        "event_type": event_type,
        "severity": severity,
        "observed": observed,
        "enrichment": enrichment,
        "derived": derived,
        "hypotheses": hypotheses,
    }


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
