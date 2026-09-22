from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

SESSION_GAP = timedelta(minutes=15)


def parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def session_identity(event: dict[str, Any]) -> tuple[str, str, str]:
    observed = event.get("observed", {})
    return (
        str(observed.get("source_ip") or "unknown"),
        str(event.get("honeypot") or "unknown"),
        str(observed.get("service") or observed.get("protocol") or "unknown"),
    )


def session_id_for(identity: tuple[str, str, str], started_at: str) -> str:
    raw = "|".join((*identity, started_at)).encode("utf-8", "replace")
    return "ses_" + hashlib.sha256(raw).hexdigest()[:20]


def should_join(last_seen: str, event_ts: str) -> bool:
    delta = parse_ts(event_ts) - parse_ts(last_seen)
    return timedelta(0) <= delta <= SESSION_GAP
