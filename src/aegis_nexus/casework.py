from __future__ import annotations

import re
from typing import Any

CASE_STATUSES = {"open", "investigating", "monitoring", "closed"}
CASE_SEVERITIES = {"info", "low", "medium", "high", "critical"}
EVIDENCE_TYPES = {"event", "session", "alert"}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class CaseValidationError(ValueError):
    pass


def _text(value: Any, field: str, maximum: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise CaseValidationError(f"{field} must be a string")
    clean = value.strip()
    if _CONTROL.search(clean):
        raise CaseValidationError(f"{field} contains control characters")
    if required and not clean:
        raise CaseValidationError(f"{field} is required")
    if len(clean) > maximum:
        raise CaseValidationError(f"{field} exceeds {maximum} characters")
    return clean


def _choice(value: Any, field: str, allowed: set[str], default: str) -> str:
    if value in (None, ""):
        return default
    clean = _text(value, field, 32).lower()
    if clean not in allowed:
        raise CaseValidationError(f"invalid {field}")
    return clean


def normalize_tags(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        candidates = value.split(",")
    elif isinstance(value, list):
        candidates = value
    else:
        raise CaseValidationError("tags must be a list or comma-separated string")
    result: list[str] = []
    seen: set[str] = set()
    for raw in candidates[:40]:
        tag = _text(raw, "tag", 48)
        if not tag:
            continue
        folded = tag.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        result.append(tag)
        if len(result) >= 20:
            break
    return result


def normalize_case_create(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CaseValidationError("case must be an object")
    return {
        "title": _text(payload.get("title"), "title", 160, required=True),
        "summary": _text(payload.get("summary"), "summary", 4000),
        "status": _choice(payload.get("status"), "status", CASE_STATUSES, "open"),
        "severity": _choice(payload.get("severity"), "severity", CASE_SEVERITIES, "info"),
        "tags": normalize_tags(payload.get("tags")),
    }


def normalize_case_update(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CaseValidationError("case update must be an object")
    result: dict[str, Any] = {}
    if "title" in payload:
        result["title"] = _text(payload.get("title"), "title", 160, required=True)
    if "summary" in payload:
        result["summary"] = _text(payload.get("summary"), "summary", 4000)
    if "status" in payload:
        result["status"] = _choice(payload.get("status"), "status", CASE_STATUSES, "open")
    if "severity" in payload:
        result["severity"] = _choice(payload.get("severity"), "severity", CASE_SEVERITIES, "info")
    if "tags" in payload:
        result["tags"] = normalize_tags(payload.get("tags"))
    if not result:
        raise CaseValidationError("no supported case fields supplied")
    return result


def normalize_evidence(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise CaseValidationError("evidence must be an object")
    evidence_type = _text(payload.get("type"), "type", 16, required=True).lower()
    if evidence_type not in EVIDENCE_TYPES:
        raise CaseValidationError("invalid evidence type")
    evidence_id = _text(payload.get("id"), "id", 128, required=True)
    return {"type": evidence_type, "id": evidence_id}


def normalize_note(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise CaseValidationError("note must be an object")
    return _text(payload.get("body"), "body", 4000, required=True)
