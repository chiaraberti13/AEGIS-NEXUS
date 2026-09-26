from __future__ import annotations

import ipaddress
import re
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


_STIX_VALUE = r"((?:\\\\.|[^'])*)"
_VALUE_PATTERN = re.compile(r"^\\[(ipv4-addr|ipv6-addr|domain-name|url):value = '" + _STIX_VALUE + r"'\\]$")
_HASH_PATTERN = re.compile(r"^\\[file:hashes\\.'(MD5|SHA-1|SHA-256)' = '" + _STIX_VALUE + r"'\\]$")


def _unescape_pattern_value(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\\\":
            result.append(char)
            index += 1
            continue
        if index + 1 >= len(value) or value[index + 1] not in {"\\\\", "'"}:
            raise StixExportError("unsupported_pattern_escape")
        result.append(value[index + 1])
        index += 2
    return "".join(result)


def import_stix_bundle(bundle: dict[str, Any], *, max_objects: int = 100_000) -> list[dict[str, Any]]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise StixExportError("stix_root_must_be_bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise StixExportError("stix_bundle_objects_must_be_list")
    limit = max(1, min(int(max_objects), 500_000))
    if len(objects) > limit:
        raise StixExportError("too_many_stix_objects")

    indicators: list[dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("pattern_type") not in (None, "stix"):
            continue
        pattern = str(obj.get("pattern") or "")
        match = _VALUE_PATTERN.fullmatch(pattern)
        kind = None
        value = None
        if match:
            object_type, encoded = match.groups()
            kind = {
                "ipv4-addr": "ip",
                "ipv6-addr": "ip",
                "domain-name": "domain",
                "url": "url",
            }[object_type]
            value = _unescape_pattern_value(encoded)
        else:
            match = _HASH_PATTERN.fullmatch(pattern)
            if match:
                algorithm, encoded = match.groups()
                kind = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}[algorithm]
                value = _unescape_pattern_value(encoded)
        if not kind or value is None:
            continue

        item: dict[str, Any] = {"type": kind, "value": value}
        labels = obj.get("labels")
        if isinstance(labels, list):
            item["labels"] = labels[:16]
        confidence = obj.get("confidence")
        if isinstance(confidence, int) and not isinstance(confidence, bool) and 0 <= confidence <= 100:
            item["confidence"] = confidence
        for source_key, target_key in (
            ("description", "description"),
            ("valid_from", "valid_from"),
            ("valid_until", "valid_until"),
        ):
            if obj.get(source_key) not in (None, ""):
                item[target_key] = obj[source_key]
        indicators.append(item)
    return indicators
