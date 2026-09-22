from __future__ import annotations

from datetime import datetime, timedelta, timezone


class EventClockError(ValueError):
    pass


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_event_clock(
    event_timestamp: str,
    collector_received_at: str,
    *,
    max_future_skew_seconds: int = 300,
) -> None:
    skew = max(0, min(int(max_future_skew_seconds), 86400))
    event_time = parse_utc(event_timestamp)
    received_time = parse_utc(collector_received_at)
    if event_time > received_time + timedelta(seconds=skew):
        raise EventClockError("event_timestamp_too_far_in_future")
