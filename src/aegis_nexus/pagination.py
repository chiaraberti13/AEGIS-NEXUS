from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any


class CursorError(ValueError):
    pass


def _valid_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise CursorError(f"invalid {field}")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CursorError(f"invalid {field}") from exc
    return value


def encode_cursor(kind: str, *, position: str, row_id: str, scope: str, since: str | None = None) -> str:
    payload: dict[str, Any] = {
        "v": 1,
        "kind": kind,
        "position": position,
        "id": row_id,
        "scope": scope,
    }
    if since is not None:
        payload["since"] = since
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(token: str, *, kind: str, scope: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > 1024:
        raise CursorError("invalid cursor")
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode((token + padding).encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise CursorError("invalid cursor") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise CursorError("invalid cursor")
    if payload.get("kind") != kind or payload.get("scope") != scope:
        raise CursorError("cursor scope mismatch")
    position = _valid_timestamp(payload.get("position"), "cursor position")
    row_id = payload.get("id")
    if not isinstance(row_id, str) or not row_id or len(row_id) > 256:
        raise CursorError("invalid cursor id")
    result = {"position": position, "id": row_id}
    if "since" in payload:
        result["since"] = _valid_timestamp(payload.get("since"), "cursor since")
    return result
