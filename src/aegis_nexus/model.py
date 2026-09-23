from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.2"
MAX_STRING = 4096
MAX_ITEMS = 128
MAX_DEPTH = 6
MAX_AUDIT_PATHS = 64
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


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


def _record_audit(audit: dict[str, Any] | None, key: str, path: str) -> None:
    if audit is None:
        return
    audit[key] = int(audit.get(key, 0)) + 1
    paths_key = f"{key}_paths"
    paths = audit.setdefault(paths_key, [])
    if isinstance(paths, list) and len(paths) < MAX_AUDIT_PATHS and path not in paths:
        paths.append(path)


def _bounded(
    value: Any,
    depth: int = 0,
    *,
    path: str = "value",
    audit: dict[str, Any] | None = None,
) -> Any:
    if depth > MAX_DEPTH:
        raise EventValidationError("payload nesting too deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EventValidationError("non-finite numeric value")
        return value
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            _record_audit(audit, "truncated_strings", path)
        return value[:MAX_STRING]
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            _record_audit(audit, "truncated_collections", path)
        return [
            _bounded(v, depth + 1, path=f"{path}[]", audit=audit)
            for v in value[:MAX_ITEMS]
        ]
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        items = list(value.items())
        if len(items) > MAX_ITEMS:
            _record_audit(audit, "truncated_collections", path)
        for raw_key, raw_value in items[:MAX_ITEMS]:
            key = str(raw_key)
            if not _SAFE_KEY.fullmatch(key):
                _record_audit(audit, "dropped_keys", path)
                continue
            clean[key] = _bounded(
                raw_value,
                depth + 1,
                path=f"{path}.{key}",
                audit=audit,
            )
        return clean
    _record_audit(audit, "coerced_values", path)
    text = str(value)
    if len(text) > MAX_STRING:
        _record_audit(audit, "truncated_strings", path)
    return text[:MAX_STRING]


def _normalization_summary(audit: dict[str, Any]) -> dict[str, Any]:
    count_keys = (
        "truncated_strings",
        "truncated_collections",
        "dropped_keys",
        "coerced_values",
        "credential_secrets_redacted",
    )
    counts = {key: int(audit.get(key, 0)) for key in count_keys}
    lossy = any(
        counts[key] > 0
        for key in ("truncated_strings", "truncated_collections", "dropped_keys", "coerced_values")
    )
    paths = {
        key: list(audit.get(f"{key}_paths", []))
        for key in count_keys
        if audit.get(f"{key}_paths")
    }
    return {
        "lossy": lossy,
        "truncated": counts["truncated_strings"] > 0 or counts["truncated_collections"] > 0,
        "redacted": counts["credential_secrets_redacted"] > 0,
        "counts": counts,
        "paths": paths,
        "limits": {
            "max_string": MAX_STRING,
            "max_items": MAX_ITEMS,
            "max_depth": MAX_DEPTH,
            "audit_paths": MAX_AUDIT_PATHS,
        },
    }


def _normalize_ip(value: Any, field: str = "source_ip") -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise EventValidationError(f"invalid {field}") from exc


def _normalize_port(value: Any, field: str) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise EventValidationError(f"invalid {field}")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise EventValidationError(f"invalid {field}") from exc
    if not 1 <= port <= 65535:
        raise EventValidationError(f"invalid {field}")
    return port


def _redact_credentials(observed: dict[str, Any], audit: dict[str, Any] | None = None) -> dict[str, Any]:
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
        _record_audit(audit, "credential_secrets_redacted", "observed.credential.password")
    return observed


def _validate_derived(derived: dict[str, Any]) -> None:
    for key in ("mitre", "cve", "ioc"):
        entries = derived.get(key, [])
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise EventValidationError(f"derived.{key} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise EventValidationError(f"derived.{key} entries must be objects")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise EventValidationError(f"derived.{key} requires evidence")
            if key in {"mitre", "cve"} and not entry.get("rationale"):
                raise EventValidationError(f"derived.{key} requires rationale")
            if key == "mitre" and not _MITRE_ID.fullmatch(str(entry.get("technique_id", ""))):
                raise EventValidationError("invalid MITRE technique_id")
            if key == "cve" and not _CVE_ID.fullmatch(str(entry.get("cve_id", ""))):
                raise EventValidationError("invalid CVE id")
            if key == "ioc" and (not entry.get("type") or entry.get("value") in (None, "")):
                raise EventValidationError("derived.ioc requires type and value")


def _validate_enrichment(enrichment: dict[str, Any]) -> None:
    for key, value in enrichment.items():
        if not isinstance(value, dict):
            raise EventValidationError(f"enrichment.{key} must be an object")
        if not value.get("source") or not value.get("observed_at"):
            raise EventValidationError(f"enrichment.{key} requires source and observed_at")
    geo = enrichment.get("geo")
    if isinstance(geo, dict) and isinstance(geo.get("data"), dict):
        data = geo["data"]
        for name, low, high in (("latitude", -90.0, 90.0), ("longitude", -180.0, 180.0)):
            if data.get(name) is not None:
                try:
                    numeric = float(data[name])
                except (TypeError, ValueError) as exc:
                    raise EventValidationError(f"invalid enrichment.geo.data.{name}") from exc
                if not low <= numeric <= high:
                    raise EventValidationError(f"invalid enrichment.geo.data.{name}")
                data[name] = numeric


def normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EventValidationError("event must be a JSON object")
    audit: dict[str, Any] = {}
    raw_observed = payload.get("observed") or {}
    if not isinstance(raw_observed, dict):
        raise EventValidationError("observed must be an object")
    observed = _bounded(
        _redact_credentials(raw_observed, audit),
        path="observed",
        audit=audit,
    )
    enrichment = _bounded(payload.get("enrichment") or {}, path="enrichment", audit=audit)
    derived = _bounded(payload.get("derived") or {}, path="derived", audit=audit)
    hypotheses = _bounded(payload.get("hypotheses") or [], path="hypotheses", audit=audit)
    if not isinstance(observed, dict) or not isinstance(enrichment, dict) or not isinstance(derived, dict):
        raise EventValidationError("observed, enrichment and derived must be objects")
    if not isinstance(hypotheses, list):
        raise EventValidationError("hypotheses must be a list")
    _validate_enrichment(enrichment)
    _validate_derived(derived)
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
    destination_ip = _normalize_ip(observed.get("destination_ip"), "destination_ip")
    if destination_ip:
        observed["destination_ip"] = destination_ip
    for field in ("source_port", "destination_port"):
        port = _normalize_port(observed.get(field), field)
        if port is not None:
            observed[field] = port
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
        "collector": {
            "normalization": _normalization_summary(audit),
        },
    }


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
