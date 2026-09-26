from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any

STIX_SPEC_VERSION = "2.1"
_STIX_NAMESPACE = uuid.UUID("0c55f6c8-4b8a-5e5b-9a20-4d7672bbd5bf")


class StixExportError(ValueError):
    pass


def _timestamp(value: Any, fallback: str) -> str:
    if value not in (None, ""):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return fallback


def _escape_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(kind: str, value: str) -> str:
    escaped = _escape_pattern(value)
    if kind == "ip":
        try:
            version = ipaddress.ip_address(value).version
        except ValueError as exc:
            raise StixExportError("invalid_ip_indicator") from exc
        object_type = "ipv4-addr" if version == 4 else "ipv6-addr"
        return f"[{object_type}:value = '{escaped}']"
    if kind == "domain":
        return f"[domain-name:value = '{escaped}']"
    if kind == "url":
        return f"[url:value = '{escaped}']"
    hashes = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
    algorithm = hashes.get(kind)
    if algorithm:
        return f"[file:hashes.'{algorithm}' = '{escaped}']"
    raise StixExportError("unsupported_indicator_type")


def export_stix_bundle(
    indicators: list[dict[str, Any]],
    *,
    source: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    created = _timestamp(generated_at, now)
    objects: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for item in indicators:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").lower()
        value = str(item.get("value") or "")
        if not kind or not value or (kind, value) in seen:
            continue
        try:
            pattern = indicator_pattern(kind, value)
        except StixExportError:
            continue
        seen.add((kind, value))
        valid_from = _timestamp(item.get("valid_from") or item.get("first_seen"), created)
        stix_id = "indicator--" + str(uuid.uuid5(_STIX_NAMESPACE, f"{source}\n{kind}\n{value}"))
        obj: dict[str, Any] = {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": created,
            "name": f"{kind}:{value}"[:256],
            "pattern_type": "stix",
            "pattern_version": STIX_SPEC_VERSION,
            "pattern": pattern,
            "valid_from": valid_from,
        }
        valid_until = item.get("valid_until")
        if valid_until:
            parsed_until = _timestamp(valid_until, "")
            if parsed_until and parsed_until > valid_from:
                obj["valid_until"] = parsed_until
        labels = item.get("labels")
        if isinstance(labels, list):
            clean = [str(label)[:128] for label in labels[:16] if str(label).strip()]
            if clean:
                obj["labels"] = clean
        if isinstance(item.get("confidence"), int) and 0 <= item["confidence"] <= 100:
            obj["confidence"] = item["confidence"]
        description = str(item.get("description") or "").strip()
        if description:
            obj["description"] = description[:512]
        objects.append(obj)

    bundle_id = "bundle--" + str(uuid.uuid4())
    return {"type": "bundle", "id": bundle_id, "objects": objects}
