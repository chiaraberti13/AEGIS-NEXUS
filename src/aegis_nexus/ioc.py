from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .migrations import enable_wal


def ioc_id(ioc_type: str, value: str) -> str:
    material = (str(ioc_type) + "\0" + str(value)).encode("utf-8", "replace")
    return "ioc_" + hashlib.sha256(material).hexdigest()[:24]


class IOCWorkspace:
    """Read-only aggregation of evidence-derived IOC across retained telemetry."""

    def __init__(self, path: str, max_events: int = 20_000):
        self.path = path
        self.max_events = max(100, min(int(max_events), 100_000))
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        enable_wal(conn)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
        return bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone())

    def _aggregate(self, hours: int = 720) -> tuple[list[dict[str, Any]], bool]:
        bounded_hours = max(1, min(int(hours), 24 * 365))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id,timestamp,source_ip,session_id,honeypot,service,derived
                FROM events
                WHERE timestamp>=?
                ORDER BY timestamp DESC,id DESC
                LIMIT ?
                """,
                (since, self.max_events + 1),
            ).fetchall()
        truncated = len(rows) > self.max_events
        rows = rows[:self.max_events]

        aggregates: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            try:
                derived = json.loads(row["derived"]) if row["derived"] else {}
            except (TypeError, json.JSONDecodeError):
                continue
            values = derived.get("ioc", []) if isinstance(derived, dict) else []
            if not isinstance(values, list):
                continue
            for raw in values[:128]:
                if not isinstance(raw, dict):
                    continue
                kind = str(raw.get("type") or "")[:64]
                value = str(raw.get("value") or "")[:512]
                if not kind or not value:
                    continue
                key = (kind, value)
                item = aggregates.get(key)
                if item is None:
                    item = {
                        "id": ioc_id(kind, value),
                        "type": kind,
                        "value": value,
                        "provenance": "derived",
                        "classification": "artifact",
                        "first_seen": row["timestamp"],
                        "last_seen": row["timestamp"],
                        "occurrences": 0,
                        "event_ids": [],
                        "session_ids": set(),
                        "source_ips": set(),
                        "honeypots": set(),
                        "services": set(),
                    }
                    aggregates[key] = item
                item["occurrences"] += 1
                item["first_seen"] = min(item["first_seen"], row["timestamp"])
                item["last_seen"] = max(item["last_seen"], row["timestamp"])
                if len(item["event_ids"]) < 256 and row["id"] not in item["event_ids"]:
                    item["event_ids"].append(row["id"])
                if row["session_id"]:
                    item["session_ids"].add(str(row["session_id"]))
                if row["source_ip"]:
                    item["source_ips"].add(str(row["source_ip"]))
                if row["honeypot"]:
                    item["honeypots"].add(str(row["honeypot"]))
                if row["service"]:
                    item["services"].add(str(row["service"]))

        result: list[dict[str, Any]] = []
        for item in aggregates.values():
            result.append({
                **item,
                "session_ids": sorted(item["session_ids"])[:256],
                "source_ips": sorted(item["source_ips"])[:256],
                "honeypots": sorted(item["honeypots"])[:128],
                "services": sorted(item["services"])[:128],
            })
        result.sort(key=lambda item: (item["last_seen"], item["occurrences"], item["id"]), reverse=True)
        return result, truncated

    def list(
        self,
        *,
        limit: int = 200,
        q: str | None = None,
        ioc_type: str | None = None,
        hours: int = 720,
    ) -> dict[str, Any]:
        items, truncated = self._aggregate(hours=hours)
        query = str(q or "").strip().casefold()[:128]
        kind = str(ioc_type or "").strip().casefold()[:64]
        if query:
            items = [
                item for item in items
                if query in item["value"].casefold() or query in item["type"].casefold()
            ]
        if kind:
            items = [item for item in items if item["type"].casefold() == kind]
        bounded_limit = max(1, min(int(limit), 500))
        return {
            "items": items[:bounded_limit],
            "analysis": {
                "event_limit": self.max_events,
                "truncated": truncated,
                "hours": max(1, min(int(hours), 24 * 365)),
                "provenance": "derived",
            },
        }

    def get(self, item_id: str, *, hours: int = 720) -> dict[str, Any] | None:
        items, truncated = self._aggregate(hours=hours)
        item = next((entry for entry in items if entry["id"] == item_id[:128]), None)
        if item is None:
            return None

        event_ids = item["event_ids"][:256]
        session_ids = item["session_ids"][:256]
        alert_ids: set[str] = set()
        case_ids: set[str] = set()
        with self.connect() as conn:
            if event_ids and self._table_exists(conn, "alert_evidence"):
                placeholders = ",".join("?" for _ in event_ids)
                rows = conn.execute(
                    f"""
                    SELECT DISTINCT alert_id FROM alert_evidence
                    WHERE evidence_type='event' AND evidence_id IN ({placeholders})
                    """,
                    event_ids,
                ).fetchall()
                alert_ids.update(str(row["alert_id"]) for row in rows)

            if self._table_exists(conn, "case_evidence"):
                references: list[tuple[str, str]] = []
                references.extend(("event", value) for value in event_ids)
                references.extend(("session", value) for value in session_ids)
                references.extend(("alert", value) for value in alert_ids)
                for evidence_type, evidence_id in references[:768]:
                    rows = conn.execute(
                        """
                        SELECT DISTINCT case_id FROM case_evidence
                        WHERE evidence_type=? AND evidence_id=?
                        """,
                        (evidence_type, evidence_id),
                    ).fetchall()
                    case_ids.update(str(row["case_id"]) for row in rows)

        return {
            **item,
            "alert_ids": sorted(alert_ids)[:256],
            "case_ids": sorted(case_ids)[:256],
            "analysis": {
                "event_limit": self.max_events,
                "truncated": truncated,
                "hours": max(1, min(int(hours), 24 * 365)),
            },
            "limitations": [
                "IOC are deterministic artifacts derived from retained telemetry, not Threat Intelligence or attribution.",
                "Relationships are limited to retained events and the configured analysis window.",
            ],
        }
