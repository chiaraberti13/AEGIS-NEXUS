"""Session storage domain for :class:`~aegis_nexus.store.Store`.

Extracted from ``store.py`` as an incremental Cycle I storage split (ADR 0003).
Session reads and projections — paginated and plain session listing, the
evidence-first session summary, and the full session bundle fetch — live here as
a mixin that ``Store`` composes, so the public API
(``Store(...).get_session(...)`` etc.) and behaviour are unchanged (guarded by
the API-contract and correlation-workspace tests).

The mixin relies, through ``self``, on the composed ``Store`` for the shared
connection (``connect``), row decoding (``_decode``) and the bounded session
window (``session_max_events``). It is read-only: it reports correlation as a
derived, heuristic-tagged conclusion and never collapses the evidence classes.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .pagination import decode_cursor, encode_cursor


class SessionStoreMixin:
    def page_sessions(
        self,
        limit: int = 100,
        q: str | None = None,
        cursor: str | None = None,
        scope: str = "",
    ) -> dict[str, Any]:
        bounded_limit = max(1, min(limit, 300))
        clauses: list[str] = []
        params: list[Any] = []
        cursor_data: dict[str, Any] | None = None
        if q:
            needle = f"%{q[:128]}%"
            clauses.append(
                "(source_ip LIKE ? OR honeypot LIKE ? OR service LIKE ? OR protocol LIKE ? OR id LIKE ?)"
            )
            params.extend([needle] * 5)
        if cursor:
            cursor_data = decode_cursor(cursor, kind="sessions", scope=scope)
            clauses.append("(last_seen < ? OR (last_seen = ? AND id < ?))")
            params.extend([cursor_data["position"], cursor_data["position"], cursor_data["id"]])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(bounded_limit + 1)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM sessions{where} ORDER BY last_seen DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
        has_more = len(rows) > bounded_limit
        rows = rows[:bounded_limit]
        items = [dict(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = encode_cursor(
                "sessions",
                position=str(last["last_seen"]),
                row_id=str(last["id"]),
                scope=scope,
            )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def list_sessions(self, limit: int = 100, q: str | None = None) -> list[dict[str, Any]]:
        return self.page_sessions(limit=limit, q=q)["items"]

    @staticmethod
    def _session_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
        credentials = 0
        commands = 0
        payloads = 0
        ids_alerts = 0
        mitre: set[str] = set()
        cves: set[str] = set()
        iocs = 0
        severity = Counter()
        event_types = Counter()
        for event in events:
            severity[event["severity"]] += 1
            event_types[event["event_type"]] += 1
            observed = event["observed"]
            derived = event["derived"]
            if isinstance(observed.get("credential"), dict):
                credentials += 1
            if observed.get("command"):
                commands += 1
            if observed.get("payload"):
                payloads += 1
            if event["event_type"] == "ids.alert":
                ids_alerts += 1
            for item in derived.get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre.add(str(item["technique_id"]))
            for item in derived.get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves.add(str(item["cve_id"]))
            iocs += len(derived.get("ioc", []) or [])
        correlation_method = "temporal_fallback"
        correlation_strength = "heuristic"
        correlation_basis = [
            "observed.source_ip",
            "honeypot",
            "observed.service",
            "observed.protocol",
            "observed.destination_port",
            "event.timestamp",
            "session_gap",
        ]
        if any(event["observed"].get("sensor_session_id") for event in events):
            correlation_method = "sensor_connection_id"
            correlation_strength = "explicit"
            correlation_basis = [
                "observed.source_ip",
                "honeypot",
                "observed.service",
                "observed.protocol",
                "observed.destination_port",
                "observed.sensor_session_id",
            ]
        elif any(event["observed"].get("flow_id") for event in events):
            correlation_method = "suricata_flow_id"
            correlation_strength = "explicit"
            correlation_basis = [
                "observed.source_ip",
                "honeypot",
                "observed.service",
                "observed.protocol",
                "observed.destination_port",
                "observed.flow_id",
                "observed.flow_start",
            ]

        return {
            "event_count": len(events),
            "correlation_method": correlation_method,
            "correlation": {
                "method": correlation_method,
                "strength": correlation_strength,
                "basis": correlation_basis,
            },
            "severity": dict(severity),
            "event_types": [{"label": key, "value": value} for key, value in event_types.most_common()],
            "credentials": credentials,
            "commands": commands,
            "payloads": payloads,
            "ids_alerts": ids_alerts,
            "mitre": sorted(mitre),
            "cves": sorted(cves),
            "iocs": iocs,
        }

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        limit = self.session_max_events
        with self.connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not session:
                return None
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE session_id=?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (session_id, limit + 1),
            ).fetchall()
        truncated = len(rows) > limit
        selected = list(rows[:limit])
        selected.reverse()
        events = [self._decode(row) for row in selected]
        summary = self._session_summary(events)
        summary["events_returned"] = len(events)
        summary["truncated"] = truncated
        return {
            "session": dict(session),
            "summary": summary,
            "events": events,
            "analysis": {
                "truncated": truncated,
                "event_limit": limit,
                "scope": "latest_session_events" if truncated else "complete_retained_session",
            },
        }
