"""Event storage domain for :class:`~aegis_nexus.store.Store`.

Extracted from ``store.py`` as an incremental Cycle I storage split (ADR 0003).
Event reads and projections — single-event fetch, SQL filter building, paginated
and plain event listing, and the behavioral/detection context windows — live
here as a mixin that ``Store`` composes, so the public API
(``Store(...).page_events(...)`` etc.) and behaviour are unchanged (guarded by
the API-contract and store tests).

The mixin relies, through ``self``, on the composed ``Store`` for the shared
connection (``connect``), row decoding (``_decode``) and the bounded analytics
window (``analytics_max_events``). It is read-only and keeps the evidence-first
provenance split intact; it never executes attacker input or re-derives data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .pagination import decode_cursor, encode_cursor
from .store_common import EVENT_FILTERS


class EventStoreMixin:
    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return self._decode(row) if row else None

    @staticmethod
    def _sql_filters(filters: dict[str, str] | None) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in (filters or {}).items():
            if value and key in EVENT_FILTERS:
                clauses.append(f"{key} = ?")
                params.append(value[:256])
        return clauses, params

    def page_events(
        self,
        limit: int = 100,
        q: str | None = None,
        filters: dict[str, str] | None = None,
        hours: int | None = None,
        cursor: str | None = None,
        scope: str = "",
    ) -> dict[str, Any]:
        bounded_limit = max(1, min(limit, 500))
        clauses, params = self._sql_filters(filters)
        since: str | None = None
        cursor_data: dict[str, Any] | None = None
        if cursor:
            cursor_data = decode_cursor(cursor, kind="events", scope=scope)
            since = cursor_data.get("since")
        elif hours is not None:
            bounded_hours = max(1, min(hours, 720))
            since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if q:
            clauses.append(
                "(source_ip LIKE ? OR event_type LIKE ? OR honeypot LIKE ? OR protocol LIKE ? OR "
                "service LIKE ? OR country LIKE ? OR asn LIKE ? OR "
                "json_remove(observed, '$.credential.password') LIKE ? OR enrichment LIKE ? OR derived LIKE ?)"
            )
            needle = f"%{q[:128]}%"
            params.extend([needle] * 10)
        if cursor_data:
            clauses.append("(timestamp < ? OR (timestamp = ? AND id < ?))")
            params.extend([cursor_data["position"], cursor_data["position"], cursor_data["id"]])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(bounded_limit + 1)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events{where} ORDER BY timestamp DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
        has_more = len(rows) > bounded_limit
        rows = rows[:bounded_limit]
        items = [self._decode(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = encode_cursor(
                "events",
                position=str(last["timestamp"]),
                row_id=str(last["id"]),
                scope=scope,
                since=since,
            )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def list_events(
        self,
        limit: int = 100,
        q: str | None = None,
        filters: dict[str, str] | None = None,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        return self.page_events(limit=limit, q=q, filters=filters, hours=hours)["items"]

    def behavioral_context(
        self,
        event: dict[str, Any],
        *,
        days: int = 30,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Return a bounded historical baseline ending at the event timestamp.

        The anchor event is explicitly excluded so its measurements cannot train
        the baseline used to evaluate itself. The event timestamp, rather than
        wall-clock time, keeps replay and regression analysis deterministic.
        """
        anchor_raw = str(event.get("timestamp") or "")
        try:
            anchor = datetime.fromisoformat(anchor_raw.replace("Z", "+00:00"))
        except ValueError:
            anchor = datetime.now(timezone.utc)
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        anchor = anchor.astimezone(timezone.utc)
        bounded_days = max(1, min(int(days), 30))
        cutoff = (anchor - timedelta(days=bounded_days)).isoformat()
        bounded_limit = max(100, min(int(limit or self.analytics_max_events), self.analytics_max_events))
        event_id = str(event.get("id") or "")
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE timestamp>=? AND timestamp<=? AND id!=?
                ORDER BY timestamp DESC,id DESC
                LIMIT ?
                """,
                (cutoff, anchor.isoformat(), event_id, bounded_limit + 1),
            ).fetchall()
        truncated = len(rows) > bounded_limit
        selected = list(rows[:bounded_limit])
        selected.reverse()
        return {
            "events": [self._decode(row) for row in selected],
            "analysis": {
                "anchor_event_id": event_id,
                "anchor_timestamp": anchor.isoformat(),
                "window_days": bounded_days,
                "event_limit": bounded_limit,
                "truncated": truncated,
                "scope": "historical_events_excluding_anchor",
            },
        }

    def detection_context(
        self,
        event: dict[str, Any],
        *,
        lookback_hours: int = 24,
        source_limit: int = 1000,
        credential_limit: int = 250,
    ) -> list[dict[str, Any]]:
        """Return bounded historical evidence for deterministic detection rules.

        The window is anchored to the event timestamp rather than wall-clock time so
        historical imports are evaluated consistently. Credential reuse is matched
        only by stored SHA-256 fingerprints; raw secrets are never queried or returned.
        """
        source_ip = str(event.get("source_ip") or (event.get("observed") or {}).get("source_ip") or "")
        anchor_raw = str(event.get("timestamp") or "")
        try:
            anchor = datetime.fromisoformat(anchor_raw.replace("Z", "+00:00"))
        except ValueError:
            return [event]
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        anchor = anchor.astimezone(timezone.utc)
        bounded_hours = max(1, min(int(lookback_hours), 168))
        since = (anchor - timedelta(hours=bounded_hours)).isoformat()
        until = anchor.isoformat()
        items: list[dict[str, Any]] = []

        with self.connect() as conn:
            if source_ip:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE source_ip=? AND timestamp>=? AND timestamp<=?
                    ORDER BY timestamp DESC,id DESC LIMIT ?
                    """,
                    (source_ip[:128], since, until, max(1, min(int(source_limit), 2000))),
                ).fetchall()
                items.extend(self._decode(row) for row in rows)

            observed = event.get("observed") if isinstance(event.get("observed"), dict) else {}
            credential = observed.get("credential") if isinstance(observed.get("credential"), dict) else {}
            fingerprint = ""
            if credential.get("password_complete") is False:
                fingerprint = str(credential.get("sensor_reported_password_sha256") or "")
            else:
                fingerprint = str(credential.get("password_sha256") or "")
            if fingerprint:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE timestamp>=? AND timestamp<=?
                      AND COALESCE(
                        CASE
                          WHEN json_extract(observed,'$.credential.password_complete')=0
                          THEN json_extract(observed,'$.credential.sensor_reported_password_sha256')
                          ELSE json_extract(observed,'$.credential.password_sha256')
                        END,
                        ''
                      )=?
                    ORDER BY timestamp DESC,id DESC LIMIT ?
                    """,
                    (since, until, fingerprint[:128], max(1, min(int(credential_limit), 1000))),
                ).fetchall()
                items.extend(self._decode(row) for row in rows)

        by_id: dict[str, dict[str, Any]] = {}
        for item in items:
            event_id = str(item.get("id") or "")
            if event_id:
                by_id[event_id] = item
        current_id = str(event.get("id") or "")
        if current_id:
            by_id[current_id] = event
        return list(by_id.values())
