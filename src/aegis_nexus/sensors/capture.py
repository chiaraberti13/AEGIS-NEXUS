from __future__ import annotations

import hashlib
from typing import Any

MAX_CAPTURE_RECORDS = 32


def bounded_text(
    value: Any,
    limit: int,
    path: str,
    audit: dict[str, Any] | None = None,
    *,
    fingerprint_original: bool = False,
) -> str:
    """Bound hostile sensor text while explicitly recording evidence loss."""
    text = "" if value is None else str(value)
    bounded_limit = max(1, int(limit))
    if len(text) <= bounded_limit:
        return text

    if audit is not None:
        entries = audit.setdefault("truncated_fields", [])
        if isinstance(entries, list) and len(entries) < MAX_CAPTURE_RECORDS:
            item: dict[str, Any] = {
                "path": path[:256],
                "original_length": len(text),
                "captured_length": bounded_limit,
            }
            if fingerprint_original:
                item["original_sha256"] = hashlib.sha256(
                    text.encode("utf-8", "replace")
                ).hexdigest()
            entries.append(item)
    return text[:bounded_limit]


def mark_truncation(
    audit: dict[str, Any] | None,
    path: str,
    *,
    original_length: int,
    captured_length: int,
    original_sha256: str | None = None,
) -> None:
    if audit is None:
        return
    entries = audit.setdefault("truncated_fields", [])
    if not isinstance(entries, list) or len(entries) >= MAX_CAPTURE_RECORDS:
        return
    item: dict[str, Any] = {
        "path": path[:256],
        "original_length": max(0, int(original_length)),
        "captured_length": max(0, int(captured_length)),
    }
    if original_sha256:
        item["original_sha256"] = str(original_sha256)[:64]
    entries.append(item)


def attach_capture_metadata(
    observed: dict[str, Any],
    audit: dict[str, Any] | None,
) -> dict[str, Any]:
    entries = (audit or {}).get("truncated_fields")
    if not isinstance(entries, list) or not entries:
        return observed
    observed["sensor_capture"] = {
        "truncated": True,
        "truncated_fields": entries[:MAX_CAPTURE_RECORDS],
    }
    return observed
