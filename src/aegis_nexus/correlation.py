from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    _gap_minutes = int(os.getenv("AEGIS_SESSION_GAP_MINUTES", "15"))
except ValueError:
    _gap_minutes = 15
SESSION_GAP = timedelta(minutes=max(1, min(_gap_minutes, 180)))


def parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def session_identity(event: dict[str, Any]) -> tuple[str, str, str, str, int]:
    observed = event.get("observed", {})
    return (
        str(observed.get("source_ip") or "unknown"),
        str(event.get("honeypot") or "unknown"),
        str(observed.get("service") or "unknown"),
        str(observed.get("protocol") or "unknown"),
        int(observed.get("destination_port") or 0),
    )


def session_id_for(identity: tuple[Any, ...], started_at: str) -> str:
    raw = "|".join(str(part) for part in (*identity, started_at)).encode("utf-8", "replace")
    return "ses_" + hashlib.sha256(raw).hexdigest()[:20]


def should_join(last_seen: str, event_ts: str) -> bool:
    delta = parse_ts(event_ts) - parse_ts(last_seen)
    return timedelta(0) <= delta <= SESSION_GAP
