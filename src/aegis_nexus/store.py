from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import uuid
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .correlation import explicit_session_token, session_id_for, session_id_for_explicit, session_identity, should_join
from .pagination import decode_cursor, encode_cursor


_EVENT_FILTERS = (
    "country",
    "asn",
    "destination_port",
    "protocol",
    "service",
    "honeypot",
    "severity",
    "source_ip",
    "session_id",
    "event_type",
)


class Store:
    def __init__(
        self,
        path: str,
        retention_days: int = 30,
        max_events: int = 500_000,
        analytics_max_events: int = 20_000,
        session_max_events: int = 5_000,
        relation_max_nodes: int = 160,
        max_cases: int = 10_000,
        case_retention_days: int = 0,
    ):
        self.path = path
        self.retention_days = max(0, retention_days)
        self.max_events = max(1_000, max_events)
        self.analytics_max_events = max(100, min(analytics_max_events, self.max_events))
        self.session_max_events = max(100, min(int(session_max_events), self.max_events))
        self.relation_max_nodes = max(32, min(int(relation_max_nodes), 1_000))
        self.max_cases = max(1, min(int(max_cases), 1_000_000))
        self.case_retention_days = max(0, min(int(case_retention_days), 3650))
        self._ingest_since_maintenance = 0
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()
        self.maintain(force=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, honeypot TEXT NOT NULL,
                    service TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'unknown',
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL, last_seen TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_at TEXT NOT NULL, honeypot TEXT NOT NULL,
                    event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT,
                    session_id TEXT NOT NULL, protocol TEXT, service TEXT, destination_port INTEGER,
                    country TEXT, asn TEXT, latitude REAL, longitude REAL,
                    observed TEXT NOT NULL, enrichment TEXT NOT NULL, derived TEXT NOT NULL,
                    hypotheses TEXT NOT NULL, collector TEXT NOT NULL DEFAULT '{}', schema_version TEXT NOT NULL,
                    collector_received_at TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_page ON events(timestamp DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, timestamp ASC);

                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS case_tags (
                    case_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY(case_id, tag),
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS case_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    UNIQUE(case_id, evidence_type, evidence_id),
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS case_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_cases_updated ON cases(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence(case_id, added_at);
                CREATE INDEX IF NOT EXISTS idx_case_history_case ON case_history(case_id, timestamp);
            """)
            event_columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
            if "received_at" not in event_columns:
                conn.execute("ALTER TABLE events ADD COLUMN received_at TEXT")
                conn.execute("UPDATE events SET received_at=timestamp WHERE received_at IS NULL")
                event_columns.add("received_at")
            if "collector_received_at" not in event_columns:
                conn.execute("ALTER TABLE events ADD COLUMN collector_received_at TEXT")
                conn.execute(
                    "UPDATE events SET collector_received_at=COALESCE(received_at, timestamp) "
                    "WHERE collector_received_at IS NULL"
                )
            if "collector" not in event_columns:
                conn.execute("ALTER TABLE events ADD COLUMN collector TEXT NOT NULL DEFAULT '{}'")
            conn.execute(
                "UPDATE events SET received_at=collector_received_at "
                "WHERE received_at IS NULL AND collector_received_at IS NOT NULL"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_received "
                "ON events(collector_received_at ASC, id ASC)"
            )

            columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)")}
            if "protocol" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT NOT NULL DEFAULT 'unknown'")
            if "destination_port" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN destination_port INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_lookup_v2 "
                "ON sessions(source_ip, honeypot, service, protocol, destination_port, last_seen)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_page "
                "ON sessions(last_seen DESC, id DESC)"
            )

    def _select_or_create_session(self, conn: sqlite3.Connection, event: dict[str, Any]) -> str:
        source_ip, honeypot, service, protocol, destination_port = session_identity(event)
        identity = (source_ip, honeypot, service, protocol, destination_port)
        explicit = explicit_session_token(event)

        if explicit:
            session_id = session_id_for_explicit(identity, explicit)
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE sessions
                    SET started_at=CASE WHEN started_at > ? THEN ? ELSE started_at END,
                        last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                        event_count=event_count+1
                    WHERE id=?
                    """,
                    (
                        event["timestamp"], event["timestamp"],
                        event["timestamp"], event["timestamp"],
                        session_id,
                    ),
                )
                return session_id
            conn.execute(
                """
                INSERT INTO sessions(
                    id,source_ip,honeypot,service,protocol,destination_port,started_at,last_seen,event_count
                ) VALUES(?,?,?,?,?,?,?,?,1)
                """,
                (
                    session_id, source_ip, honeypot, service, protocol, destination_port,
                    event["timestamp"], event["timestamp"],
                ),
            )
            return session_id

        row = conn.execute(
            """
            SELECT * FROM sessions
            WHERE source_ip=? AND honeypot=? AND service=? AND protocol=? AND destination_port=?
            ORDER BY last_seen DESC LIMIT 1
            """,
            (source_ip, honeypot, service, protocol, destination_port),
        ).fetchone()
        if row and should_join(row["last_seen"], event["timestamp"]):
            conn.execute(
                "UPDATE sessions SET last_seen=?, event_count=event_count+1 WHERE id=?",
                (event["timestamp"], row["id"]),
            )
            return row["id"]

        session_id = session_id_for(identity, event["timestamp"])
        conn.execute(
            """
            INSERT INTO sessions(
                id,source_ip,honeypot,service,protocol,destination_port,started_at,last_seen,event_count
            ) VALUES(?,?,?,?,?,?,?,?,1)
            """,
            (session_id, source_ip, honeypot, service, protocol, destination_port, event["timestamp"], event["timestamp"]),
        )
        return session_id

    @staticmethod
    def _geo(enrichment: dict[str, Any]) -> tuple[str | None, str | None, float | None, float | None]:
        geo = enrichment.get("geo") if isinstance(enrichment.get("geo"), dict) else {}
        asn = enrichment.get("asn") if isinstance(enrichment.get("asn"), dict) else {}
        data = geo.get("data") if isinstance(geo.get("data"), dict) else {}
        asn_data = asn.get("data") if isinstance(asn.get("data"), dict) else {}
        return data.get("country"), asn_data.get("asn"), data.get("latitude"), data.get("longitude")

    def ingest(self, event: dict[str, Any], collector_received_at: str | None = None) -> dict[str, Any]:
        observed = event["observed"]
        received_at = collector_received_at or datetime.now(timezone.utc).isoformat()
        country, asn, latitude, longitude = self._geo(event["enrichment"])
        with self.connect() as conn:
            session_id = self._select_or_create_session(conn, event)
            conn.execute("""
                INSERT INTO events(
                    id,timestamp,received_at,honeypot,event_type,severity,source_ip,session_id,protocol,service,
                    destination_port,country,asn,latitude,longitude,observed,enrichment,derived,hypotheses,collector,schema_version,
                    collector_received_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event["id"], event["timestamp"], received_at, event["honeypot"], event["event_type"], event["severity"],
                observed.get("source_ip"), session_id, observed.get("protocol"), observed.get("service"),
                observed.get("destination_port"), country, asn, latitude, longitude,
                json.dumps(event["observed"], ensure_ascii=False),
                json.dumps(event["enrichment"], ensure_ascii=False),
                json.dumps(event["derived"], ensure_ascii=False),
                json.dumps(event["hypotheses"], ensure_ascii=False),
                json.dumps(event.get("collector", {}), ensure_ascii=False),
                event["schema_version"], received_at,
            ))
        self._ingest_since_maintenance += 1
        self.maintain()
        safe_event = self._export_safe_event(event)
        return {
            **safe_event,
            "session_id": session_id,
            "received_at": received_at,
            "collector_received_at": received_at,
        }

    def maintain(self, force: bool = False) -> dict[str, int]:
        if not force and self._ingest_since_maintenance < 100:
            return {"retention_deleted": 0, "capacity_deleted": 0, "case_retention_deleted": 0}
        self._ingest_since_maintenance = 0
        retention_deleted = self.prune(self.retention_days)
        case_retention_deleted = self.prune_cases(self.case_retention_days)
        capacity_deleted = 0
        with self.connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
            overflow = max(0, int(count) - self.max_events)
            if overflow:
                cur = conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY collector_received_at ASC, id ASC LIMIT ?)",
                    (overflow,),
                )
                capacity_deleted = cur.rowcount
                conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")
        with self.connect() as checkpoint_conn:
            checkpoint_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {
            "retention_deleted": retention_deleted,
            "capacity_deleted": capacity_deleted,
            "case_retention_deleted": case_retention_deleted,
        }

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for field in ("observed", "enrichment", "derived", "hypotheses", "collector"):
            raw = data.get(field)
            data[field] = json.loads(raw) if isinstance(raw, str) and raw else {}
        observed = data.get("observed")
        if isinstance(observed, dict):
            credential = observed.get("credential")
            if isinstance(credential, dict):
                # Cleartext credential storage is an explicit database-retention choice only.
                # Operator APIs/UI always receive the deterministic fingerprint and length,
                # never the collected secret itself.
                credential.pop("password", None)
        return data

    def prune(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM events WHERE collector_received_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")
        return deleted

    def prune_cases(self, retention_days: int | None = None) -> int:
        days = self.case_retention_days if retention_days is None else max(0, int(retention_days))
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute(
                """
                DELETE FROM cases
                WHERE status='closed' AND closed_at IS NOT NULL AND closed_at < ?
                """,
                (cutoff,),
            )
            return cur.rowcount

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return self._decode(row) if row else None

    @staticmethod
    def _sql_filters(filters: dict[str, str] | None) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in (filters or {}).items():
            if value and key in _EVENT_FILTERS:
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

    @staticmethod
    def _case_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def _case_tags(self, conn: sqlite3.Connection, case_id: str) -> list[str]:
        rows = conn.execute(
            "SELECT tag FROM case_tags WHERE case_id=? ORDER BY tag COLLATE NOCASE",
            (case_id,),
        ).fetchall()
        return [str(row["tag"]) for row in rows]

    def _case_history(self, conn: sqlite3.Connection, case_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT id,timestamp,action,detail FROM case_history WHERE case_id=? ORDER BY id ASC LIMIT 500",
            (case_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["detail"] = json.loads(item["detail"])
            except (TypeError, json.JSONDecodeError):
                item["detail"] = {}
            result.append(item)
        return result

    def _case_log(self, conn: sqlite3.Connection, case_id: str, action: str, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO case_history(case_id,timestamp,action,detail) VALUES(?,?,?,?)",
            (
                case_id,
                self._case_now(),
                action[:64],
                json.dumps(detail, ensure_ascii=False, sort_keys=True),
            ),
        )

    def create_case(self, data: dict[str, Any]) -> dict[str, Any]:
        self.prune_cases()
        case_id = "case_" + uuid.uuid4().hex[:20]
        now = self._case_now()
        closed_at = now if data["status"] == "closed" else None
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO cases(id,title,status,severity,summary,created_at,updated_at,closed_at)
                SELECT ?,?,?,?,?,?,?,?
                WHERE (SELECT COUNT(*) FROM cases) < ?
                """,
                (
                    case_id,
                    data["title"],
                    data["status"],
                    data["severity"],
                    data["summary"],
                    now,
                    now,
                    closed_at,
                    self.max_cases,
                ),
            )
            if cur.rowcount != 1:
                raise ValueError("case_capacity")
            for tag in data.get("tags", []):
                conn.execute("INSERT OR IGNORE INTO case_tags(case_id,tag) VALUES(?,?)", (case_id, tag))
            self._case_log(
                conn,
                case_id,
                "created",
                {
                    "status": data["status"],
                    "severity": data["severity"],
                    "classification_provenance": "analyst",
                },
            )
        return self.get_case(case_id) or {}

    def delete_case(self, case_id: str) -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return "not_found"
            if row["status"] != "closed":
                return "case_not_closed"
            conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
            return "deleted"

    def list_cases(
        self,
        limit: int = 100,
        q: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status[:32])
        if q:
            needle = f"%{q[:128]}%"
            clauses.append(
                "(id LIKE ? OR title LIKE ? OR summary LIKE ? OR EXISTS("
                "SELECT 1 FROM case_tags ct WHERE ct.case_id=cases.id AND ct.tag LIKE ?))"
            )
            params.extend([needle, needle, needle, needle])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 300)))
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT cases.*,
                    (SELECT COUNT(*) FROM case_evidence ce WHERE ce.case_id=cases.id) AS evidence_count,
                    (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id=cases.id) AS note_count
                FROM cases
                {where}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["tags"] = self._case_tags(conn, item["id"])
                item["classification_provenance"] = "analyst"
                result.append(item)
        return result

    def _resolve_case_evidence(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        evidence_type = item["evidence_type"]
        evidence_id = item["evidence_id"]
        item["available"] = False
        item["summary"] = None
        if evidence_type == "event":
            event = conn.execute(
                """
                SELECT id,timestamp,event_type,severity,source_ip,session_id,honeypot,service,protocol,destination_port
                FROM events WHERE id=?
                """,
                (evidence_id,),
            ).fetchone()
            if event:
                item["available"] = True
                item["summary"] = dict(event)
        elif evidence_type == "session":
            session = conn.execute(
                """
                SELECT id,source_ip,honeypot,service,protocol,destination_port,started_at,last_seen,event_count
                FROM sessions WHERE id=?
                """,
                (evidence_id,),
            ).fetchone()
            if session:
                item["available"] = True
                item["summary"] = dict(session)
        return item

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                return None
            evidence_rows = conn.execute(
                """
                SELECT id,case_id,evidence_type,evidence_id,added_at
                FROM case_evidence WHERE case_id=? ORDER BY added_at ASC,id ASC
                """,
                (case_id,),
            ).fetchall()
            note_rows = conn.execute(
                "SELECT id,body,created_at FROM case_notes WHERE case_id=? ORDER BY id ASC LIMIT 500",
                (case_id,),
            ).fetchall()
            result = dict(case)
            result["tags"] = self._case_tags(conn, case_id)
            result["evidence"] = [self._resolve_case_evidence(conn, row) for row in evidence_rows]
            result["notes"] = [dict(row) for row in note_rows]
            result["history"] = self._case_history(conn, case_id)
            result["classification_provenance"] = "analyst"
            result["evidence_provenance"] = "telemetry_reference"
            return result

    def update_case(self, case_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        with self.connect() as conn:
            existing = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not existing:
                return None
            fields: list[str] = []
            params: list[Any] = []
            changed: dict[str, Any] = {}
            for key in ("title", "summary", "status", "severity"):
                if key in data:
                    fields.append(f"{key}=?")
                    params.append(data[key])
                    changed[key] = data[key]
            now = self._case_now()
            if data.get("status") == "closed" and existing["status"] != "closed":
                fields.append("closed_at=?")
                params.append(now)
            elif "status" in data and data["status"] != "closed" and existing["status"] == "closed":
                fields.append("closed_at=NULL")
            if fields:
                fields.append("updated_at=?")
                params.append(now)
                params.append(case_id)
                conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id=?", params)
            if "tags" in data:
                conn.execute("DELETE FROM case_tags WHERE case_id=?", (case_id,))
                for tag in data["tags"]:
                    conn.execute("INSERT OR IGNORE INTO case_tags(case_id,tag) VALUES(?,?)", (case_id, tag))
                changed["tags"] = data["tags"]
            if changed:
                if not fields:
                    conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
                changed["classification_provenance"] = "analyst"
                self._case_log(conn, case_id, "updated", changed)
        return self.get_case(case_id)

    def add_case_evidence(self, case_id: str, evidence_type: str, evidence_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                return None
            existing = conn.execute(
                """
                SELECT 1 FROM case_evidence
                WHERE case_id=? AND evidence_type=? AND evidence_id=?
                """,
                (case_id, evidence_type, evidence_id),
            ).fetchone()
            if existing:
                return self.get_case(case_id)
            evidence_count = conn.execute(
                "SELECT COUNT(*) AS count FROM case_evidence WHERE case_id=?",
                (case_id,),
            ).fetchone()["count"]
            if int(evidence_count) >= 1000:
                raise ValueError("case_evidence_limit")
            if evidence_type == "event":
                available = conn.execute("SELECT 1 FROM events WHERE id=?", (evidence_id,)).fetchone()
            else:
                available = conn.execute("SELECT 1 FROM sessions WHERE id=?", (evidence_id,)).fetchone()
            if not available:
                raise ValueError("evidence_not_found")
            now = self._case_now()
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO case_evidence(case_id,evidence_type,evidence_id,added_at)
                VALUES(?,?,?,?)
                """,
                (case_id, evidence_type, evidence_id, now),
            )
            if cur.rowcount:
                conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
                self._case_log(
                    conn,
                    case_id,
                    "evidence_added",
                    {"type": evidence_type, "id": evidence_id, "provenance": "telemetry_reference"},
                )
        return self.get_case(case_id)

    def remove_case_evidence(self, case_id: str, evidence_row_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                return None
            row = conn.execute(
                "SELECT evidence_type,evidence_id FROM case_evidence WHERE id=? AND case_id=?",
                (evidence_row_id, case_id),
            ).fetchone()
            if not row:
                raise ValueError("evidence_not_found")
            conn.execute("DELETE FROM case_evidence WHERE id=? AND case_id=?", (evidence_row_id, case_id))
            now = self._case_now()
            conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
            self._case_log(
                conn,
                case_id,
                "evidence_removed",
                {"type": row["evidence_type"], "id": row["evidence_id"]},
            )
        return self.get_case(case_id)

    def add_case_note(self, case_id: str, body: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                return None
            note_count = conn.execute(
                "SELECT COUNT(*) AS count FROM case_notes WHERE case_id=?",
                (case_id,),
            ).fetchone()["count"]
            if int(note_count) >= 500:
                raise ValueError("case_note_limit")
            now = self._case_now()
            cur = conn.execute(
                "INSERT INTO case_notes(case_id,body,created_at) VALUES(?,?,?)",
                (case_id, body, now),
            )
            conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
            self._case_log(
                conn,
                case_id,
                "note_added",
                {"note_id": cur.lastrowid, "provenance": "analyst_note"},
            )
        return self.get_case(case_id)

    def case_report(self, case_id: str) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if not case:
            return None
        available = sum(1 for item in case["evidence"] if item["available"])
        unavailable = len(case["evidence"]) - available
        return {
            "report_type": "investigation_case",
            "generated_at": self._case_now(),
            "case": {
                "id": case["id"],
                "title": case["title"],
                "status": case["status"],
                "severity": case["severity"],
                "summary": case["summary"],
                "tags": case["tags"],
                "created_at": case["created_at"],
                "updated_at": case["updated_at"],
                "closed_at": case["closed_at"],
                "classification_provenance": "analyst",
            },
            "evidence": case["evidence"],
            "notes": [
                {
                    "id": note["id"],
                    "created_at": note["created_at"],
                    "body": note["body"],
                    "provenance": "analyst_note",
                }
                for note in case["notes"]
            ],
            "history": case["history"],
            "statistics": {
                "evidence_references": len(case["evidence"]),
                "available_references": available,
                "unavailable_references": unavailable,
                "notes": len(case["notes"]),
            },
            "limitations": [
                "Case status, severity, summary, tags and notes are analyst classifications or annotations, not observed telemetry.",
                "Evidence entries are references to source telemetry and do not extend its configured retention period.",
                "Unavailable evidence means the source telemetry is no longer present or accessible in the current dataset.",
                "IP, geolocation, ASN and external reputation context do not establish human identity or attribution.",
            ],
        }

    @staticmethod
    def _extract_external_enrichment(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for event in events:
            enrichment = event.get("enrichment") or {}
            for kind, value in enrichment.items():
                if not isinstance(value, dict):
                    continue
                source = value.get("source")
                observed_at = value.get("observed_at")
                data = value.get("data")
                if not source or not observed_at:
                    continue
                fingerprint = json.dumps(
                    {"kind": kind, "source": source, "data": data},
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                entries.append({
                    "kind": kind,
                    "source": source,
                    "observed_at": observed_at,
                    "data": data,
                    "event_id": event["id"],
                    "provenance": "external_enrichment",
                    "classification": "threat_intelligence" if kind == "threat_context" else "context_enrichment",
                })
        entries.sort(key=lambda item: str(item.get("observed_at") or ""), reverse=True)
        return entries[:100]

    @staticmethod
    def _counter_items(counter: Counter, limit: int = 10) -> list[dict[str, Any]]:
        return [{"label": str(label), "value": int(value)} for label, value in counter.most_common(limit)]

    @staticmethod
    def _credential_secret_summary(credential: dict[str, Any]) -> dict[str, Any] | None:
        complete = credential.get("password_complete") is not False
        if not complete and credential.get("sensor_reported_password_sha256"):
            digest = str(credential["sensor_reported_password_sha256"])
            length = credential.get("sensor_reported_password_length")
            return {
                "label": f"sensor-sha256:{digest[:16]} · len:{length if length is not None else '?'} · truncated",
                "sha256": digest,
                "length": length,
                "complete": False,
                "provenance": "sensor_reported_original",
            }
        digest = credential.get("password_sha256")
        if not digest:
            return None
        length = credential.get("password_length")
        return {
            "label": f"sha256:{str(digest)[:16]} · len:{length if length is not None else '?'}",
            "sha256": str(digest),
            "length": length,
            "complete": complete,
            "provenance": "collector_received_value",
        }

    def ip_profile(self, ip: str) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 500",
                (ip,),
            ).fetchall()
        events = [self._decode(row) for row in rows]
        first_seen = min((event["timestamp"] for event in events), default=None)
        last_seen = max((event["timestamp"] for event in events), default=None)
        severities = Counter(event["severity"] for event in events)
        event_types = Counter(event["event_type"] for event in events)
        honeypots = Counter(event["honeypot"] for event in events)
        usernames: Counter[str] = Counter()
        credential_secrets: Counter[str] = Counter()
        commands: Counter[str] = Counter()
        payloads: Counter[str] = Counter()
        ids_alerts: Counter[str] = Counter()
        mitre: Counter[str] = Counter()
        cves: Counter[str] = Counter()
        iocs: Counter[str] = Counter()

        for event in events:
            observed = event.get("observed") or {}
            derived = event.get("derived") or {}
            credential = observed.get("credential")
            if isinstance(credential, dict):
                if credential.get("username"):
                    usernames[str(credential["username"])[:160]] += 1
                secret = self._credential_secret_summary(credential)
                if secret:
                    credential_secrets[secret["label"]] += 1
            if observed.get("command"):
                commands[str(observed["command"])[:160]] += 1
            if observed.get("payload"):
                payloads[str(observed["payload"])[:160]] += 1
            if event.get("event_type") == "ids.alert":
                alert = observed.get("alert") if isinstance(observed.get("alert"), dict) else {}
                signature = observed.get("signature") or alert.get("signature")
                if signature:
                    ids_alerts[str(signature)[:180]] += 1
            for item in derived.get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            for item in derived.get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves[str(item["cve_id"])] += 1
            for item in derived.get("ioc", []) or []:
                if isinstance(item, dict) and item.get("type") and item.get("value") not in (None, ""):
                    iocs[f"{item['type']}: {str(item['value'])[:160]}"] += 1

        external_enrichment = self._extract_external_enrichment(events)
        threat_intelligence = [
            item for item in external_enrichment
            if item.get("classification") == "threat_intelligence"
        ]
        return {
            "source_ip": ip,
            "event_count": len(events),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "sessions": sorted({event["session_id"] for event in events}),
            "countries": sorted({event["country"] for event in events if event.get("country")}),
            "asns": sorted({event["asn"] for event in events if event.get("asn")}),
            "services": sorted({event["service"] for event in events if event.get("service")}),
            "protocols": sorted({event["protocol"] for event in events if event.get("protocol")}),
            "destination_ports": sorted({event["destination_port"] for event in events if event.get("destination_port")}),
            "severity": dict(severities),
            "activity": {
                "event_types": self._counter_items(event_types),
                "honeypots": self._counter_items(honeypots),
                "usernames": self._counter_items(usernames),
                "credential_secret_fingerprints": self._counter_items(credential_secrets),
                "commands": self._counter_items(commands),
                "payloads": self._counter_items(payloads),
                "ids_alerts": self._counter_items(ids_alerts),
                "mitre": self._counter_items(mitre),
                "cves": self._counter_items(cves),
                "iocs": self._counter_items(iocs),
            },
            "external_enrichment": external_enrichment,
            "threat_intelligence": threat_intelligence,
            "events": events,
            "attribution_limit": (
                "IP, ASN, geolocation and reputation enrichment describe infrastructure context; "
                "they do not identify the human operator or prove attribution."
            ),
        }

    def threat_intelligence(self, ip: str) -> dict[str, Any]:
        profile = self.ip_profile(ip)
        return {
            "source_ip": ip,
            "items": profile["external_enrichment"],
            "threat_intelligence_items": profile["threat_intelligence"],
            "context_enrichment_items": [
                item for item in profile["external_enrichment"]
                if item.get("classification") != "threat_intelligence"
            ],
            "limitations": [
                "External enrichment may be stale, incomplete or inaccurate.",
                "VPNs, proxies, NAT, hosting providers and compromised systems can obscure origin.",
                "GeoIP/ASN context is enrichment, not threat intelligence by itself.",
                "No threat actor or campaign attribution is inferred by AEGIS-NEXUS.",
            ],
        }

    def operational_health(self, min_free_bytes: int = 67_108_864) -> dict[str, Any]:
        threshold = max(0, int(min_free_bytes))
        database_ready = False
        try:
            with self.connect() as conn:
                conn.execute("SELECT 1").fetchone()
            database_ready = True
        except sqlite3.Error:
            database_ready = False

        storage_free_bytes: int | None = None
        try:
            storage_free_bytes = int(shutil.disk_usage(Path(self.path).parent).free)
        except OSError:
            storage_free_bytes = None
        storage_ready = storage_free_bytes is not None and storage_free_bytes >= threshold

        return {
            "ready": database_ready and storage_ready,
            "database_ready": database_ready,
            "storage_ready": storage_ready,
            "storage_free_bytes": storage_free_bytes,
            "min_free_bytes": threshold,
        }

    def sensor_telemetry_observation(
        self,
        configured_sensor_ids: list[str] | tuple[str, ...] | set[str] | None = None,
        recent_hours: int = 24,
    ) -> dict[str, Any]:
        bounded_hours = max(1, min(int(recent_hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    honeypot,
                    MAX(collector_received_at) AS last_received_at,
                    MAX(timestamp) AS latest_event_timestamp,
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN collector_received_at >= ? THEN 1 ELSE 0 END) AS recent_events
                FROM events
                GROUP BY honeypot
                ORDER BY honeypot COLLATE NOCASE
                """,
                (since,),
            ).fetchall()

        observed = {
            str(row["honeypot"]): {
                "sensor_id": str(row["honeypot"]),
                "configured": False,
                "last_received_at": row["last_received_at"],
                "latest_event_timestamp": row["latest_event_timestamp"],
                "total_events": int(row["total_events"] or 0),
                "recent_events": int(row["recent_events"] or 0),
            }
            for row in rows
        }
        configured = {
            str(sensor_id)[:96]
            for sensor_id in (configured_sensor_ids or [])
            if str(sensor_id)
        }
        for sensor_id in configured:
            item = observed.setdefault(
                sensor_id,
                {
                    "sensor_id": sensor_id,
                    "configured": True,
                    "last_received_at": None,
                    "latest_event_timestamp": None,
                    "total_events": 0,
                    "recent_events": 0,
                },
            )
            item["configured"] = True

        items = [observed[key] for key in sorted(observed, key=str.casefold)]
        return {
            "recent_hours": bounded_hours,
            "configured_sensors": len(configured),
            "configured_with_recent_telemetry": sum(
                1 for item in items if item["configured"] and item["recent_events"] > 0
            ),
            "observed_sensor_ids": len(items),
            "items": items,
            "interpretation": (
                "Telemetry timestamps indicate collector receipt, not proof that a sensor is online or offline."
            ),
        }

    def filter_options(self, hours: int = 720) -> dict[str, list[str]]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        result: dict[str, list[str]] = {}
        columns = ("country", "asn", "destination_port", "protocol", "service", "honeypot", "severity", "event_type")
        with self.connect() as conn:
            for column in columns:
                rows = conn.execute(
                    f"""
                    SELECT {column} AS value, COUNT(*) AS count
                    FROM events
                    WHERE timestamp >= ? AND {column} IS NOT NULL AND {column} != ''
                    GROUP BY {column}
                    ORDER BY count DESC, value ASC
                    LIMIT 100
                    """,
                    (since,),
                ).fetchall()
                result[column] = [str(row["value"]) for row in rows]
        return result

    @staticmethod
    def _event_matches_filters(event: dict[str, Any], filters: dict[str, str] | None) -> bool:
        for key, value in (filters or {}).items():
            if value and key in _EVENT_FILTERS and str(event.get(key) or "") != value:
                return False
        return True

    @staticmethod
    def _matches_q(event: dict[str, Any], q: str | None) -> bool:
        if not q:
            return True
        needle = q[:128].casefold()
        searchable = (
            event.get("source_ip"),
            event.get("event_type"),
            event.get("honeypot"),
            event.get("protocol"),
            event.get("service"),
            event.get("country"),
            event.get("asn"),
            json.dumps(event.get("observed", {}), ensure_ascii=False),
            json.dumps(event.get("enrichment", {}), ensure_ascii=False),
            json.dumps(event.get("derived", {}), ensure_ascii=False),
        )
        return any(needle in str(value).casefold() for value in searchable if value not in (None, ""))

    @staticmethod
    def _top(events: list[dict[str, Any]], field: str, n: int = 10) -> list[dict[str, Any]]:
        counts = Counter(str(event.get(field)) for event in events if event.get(field) not in (None, ""))
        return [{"label": label, "value": value} for label, value in counts.most_common(n)]

    def dashboard(
        self,
        hours: int = 24,
        include_simulation: bool = False,
        q: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        clauses = ["timestamp >= ?"]
        params: list[Any] = [since]
        filter_clauses, filter_params = self._sql_filters(filters)
        clauses.extend(filter_clauses)
        params.extend(filter_params)
        if q:
            clauses.append(
                "(source_ip LIKE ? OR event_type LIKE ? OR honeypot LIKE ? OR protocol LIKE ? OR "
                "service LIKE ? OR country LIKE ? OR asn LIKE ? OR "
                "json_remove(observed, '$.credential.password') LIKE ? OR enrichment LIKE ? OR derived LIKE ?)"
            )
            needle = f"%{q[:128]}%"
            params.extend([needle] * 10)
        params.append(self.analytics_max_events + 1)
        where = " AND ".join(clauses)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        truncated = len(rows) > self.analytics_max_events
        if truncated:
            rows = rows[:self.analytics_max_events]
        events = [self._decode(row) for row in reversed(rows)]
        if not include_simulation:
            events = [event for event in events if event["derived"].get("data_mode") != "simulation"]

        timeline: dict[str, int] = defaultdict(int)
        unique_source_timeline: dict[str, set[str]] = defaultdict(set)
        heatmap = [[0 for _ in range(24)] for _ in range(7)]
        credentials, credential_secrets = Counter(), Counter()
        commands, payloads = Counter(), Counter()
        mitre, cves, ids, iocs = Counter(), Counter(), Counter(), Counter()
        normalization_counts: Counter[str] = Counter()
        sensor_capture_counts: Counter[str] = Counter()
        map_groups: dict[tuple[str, float, float], dict[str, Any]] = {}

        for event in events:
            normalization = (event.get("collector") or {}).get("normalization")
            if isinstance(normalization, dict):
                counts = normalization.get("counts")
                counts = counts if isinstance(counts, dict) else {}
                for key in (
                    "truncated_strings",
                    "truncated_collections",
                    "dropped_keys",
                    "coerced_values",
                    "credential_secrets_redacted",
                ):
                    try:
                        normalization_counts[key] += max(0, int(counts.get(key) or 0))
                    except (TypeError, ValueError):
                        continue
                if normalization.get("truncated"):
                    normalization_counts["events_with_truncation"] += 1
                if normalization.get("lossy"):
                    normalization_counts["events_with_lossy_normalization"] += 1
                if normalization.get("redacted"):
                    normalization_counts["events_with_credential_redaction"] += 1

            sensor_capture = (event.get("observed") or {}).get("sensor_capture")
            if isinstance(sensor_capture, dict):
                if sensor_capture.get("truncated"):
                    sensor_capture_counts["events_with_truncation"] += 1
                if sensor_capture.get("rejected"):
                    sensor_capture_counts["events_with_rejection"] += 1
                entries = sensor_capture.get("truncated_fields")
                if isinstance(entries, list):
                    sensor_capture_counts["truncated_fields"] += len(entries)

            ts = datetime.fromisoformat(event["timestamp"])
            bucket = ts.strftime("%Y-%m-%dT%H:00Z")
            timeline[bucket] += 1
            if event.get("source_ip"):
                unique_source_timeline[bucket].add(str(event["source_ip"]))
            heatmap[ts.weekday()][ts.hour] += 1
            credential = event["observed"].get("credential")
            if isinstance(credential, dict):
                if credential.get("username"):
                    credentials[str(credential["username"])] += 1
                secret = self._credential_secret_summary(credential)
                if secret:
                    credential_secrets[secret["label"]] += 1
            if event["observed"].get("command"):
                commands[str(event["observed"]["command"])[:120]] += 1
            if event["observed"].get("payload"):
                payloads[str(event["observed"]["payload"])[:120]] += 1
            for item in event["derived"].get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            for item in event["derived"].get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves[str(item["cve_id"])] += 1
            for item in event["derived"].get("ioc", []) or []:
                if isinstance(item, dict) and item.get("type") and item.get("value") not in (None, ""):
                    label = f"{item['type']}: {str(item['value'])[:140]}"
                    iocs[label] += 1
            if event["event_type"] == "ids.alert":
                alert = event["observed"].get("alert") if isinstance(event["observed"].get("alert"), dict) else {}
                signature = event["observed"].get("signature") or alert.get("signature")
                if signature:
                    ids[str(signature)[:160]] += 1

            if (
                event.get("source_ip")
                and event.get("latitude") is not None
                and event.get("longitude") is not None
            ):
                lat = round(float(event["latitude"]), 4)
                lon = round(float(event["longitude"]), 4)
                map_key = (str(event["source_ip"]), lat, lon)
                point = map_groups.setdefault(map_key, {
                    "lat": lat,
                    "lon": lon,
                    "source_ip": event["source_ip"],
                    "country": event.get("country"),
                    "asn": event.get("asn"),
                    "count": 0,
                    "session_ids": set(),
                    "services": set(),
                    "destination_ports": set(),
                    "honeypots": set(),
                    "last_seen": event["timestamp"],
                })
                point["count"] += 1
                point["session_ids"].add(event["session_id"])
                if event.get("service"):
                    point["services"].add(event["service"])
                if event.get("destination_port"):
                    point["destination_ports"].add(event["destination_port"])
                if event.get("honeypot"):
                    point["honeypots"].add(event["honeypot"])
                if event["timestamp"] > point["last_seen"]:
                    point["last_seen"] = event["timestamp"]

        map_points = []
        for point in map_groups.values():
            map_points.append({
                "lat": point["lat"],
                "lon": point["lon"],
                "source_ip": point["source_ip"],
                "country": point["country"],
                "asn": point["asn"],
                "count": point["count"],
                "session_count": len(point["session_ids"]),
                "services": sorted(point["services"])[:8],
                "destination_ports": sorted(point["destination_ports"])[:16],
                "honeypots": sorted(point["honeypots"])[:8],
                "last_seen": point["last_seen"],
            })
        map_points.sort(key=lambda item: (int(item["count"]), str(item["last_seen"])), reverse=True)

        return {
            "window_hours": bounded_hours,
            "query": q or "",
            "filters": {key: value for key, value in (filters or {}).items() if value},
            "analysis": {
                "truncated": truncated,
                "event_limit": self.analytics_max_events,
                "scope": "latest_matching_events",
                "provenance": {
                    "observed": ["events", "source_ip", "destination_port", "protocol", "service", "honeypot", "credentials", "commands", "payloads", "ids_alerts"],
                    "enrichment": ["country", "asn", "map_points"],
                    "derived": ["sessions", "credential_secret_fingerprints", "iocs", "mitre", "cves"],
                    "collector": ["normalization"],
                    "hypotheses_in_analytics": False,
                },
            },
            "totals": {
                "events": len(events),
                "unique_source_ip": len({event["source_ip"] for event in events if event.get("source_ip")}),
                "sessions": len({event["session_id"] for event in events}),
                "critical": sum(1 for event in events if event["severity"] == "critical"),
            },
            "data_quality": {
                "events_with_truncation": int(normalization_counts["events_with_truncation"]),
                "events_with_lossy_normalization": int(normalization_counts["events_with_lossy_normalization"]),
                "events_with_credential_redaction": int(normalization_counts["events_with_credential_redaction"]),
                "truncated_strings": int(normalization_counts["truncated_strings"]),
                "truncated_collections": int(normalization_counts["truncated_collections"]),
                "dropped_keys": int(normalization_counts["dropped_keys"]),
                "coerced_values": int(normalization_counts["coerced_values"]),
                "credential_secrets_redacted": int(normalization_counts["credential_secrets_redacted"]),
                "events_with_sensor_truncation": int(sensor_capture_counts["events_with_truncation"]),
                "events_with_sensor_rejection": int(sensor_capture_counts["events_with_rejection"]),
                "sensor_truncated_fields": int(sensor_capture_counts["truncated_fields"]),
            },
            "timeline": [{"label": key, "value": timeline[key]} for key in sorted(timeline)],
            "unique_source_ip_timeline": [
                {"label": key, "value": len(unique_source_timeline[key])}
                for key in sorted(unique_source_timeline)
            ],
            "heatmap": heatmap,
            "source_ip": self._top(events, "source_ip"),
            "event_type": self._top(events, "event_type"),
            "severity": self._top(events, "severity"),
            "country": self._top(events, "country"),
            "asn": self._top(events, "asn"),
            "destination_port": self._top(events, "destination_port"),
            "protocol": self._top(events, "protocol"),
            "service": self._top(events, "service"),
            "honeypot": self._top(events, "honeypot"),
            "credentials": self._counter_items(credentials),
            "credential_secret_fingerprints": self._counter_items(credential_secrets),
            "commands": self._counter_items(commands),
            "payloads": self._counter_items(payloads),
            "ids_alerts": self._counter_items(ids),
            "iocs": self._counter_items(iocs),
            "mitre": self._counter_items(mitre),
            "cves": self._counter_items(cves),
            "map_points": map_points[:400],
        }

    @staticmethod
    def _export_safe_event(event: dict[str, Any]) -> dict[str, Any]:
        safe = deepcopy(event)
        observed = safe.get("observed")
        if isinstance(observed, dict):
            credential = observed.get("credential")
            if isinstance(credential, dict):
                credential.pop("password", None)
        return safe

    def report(self, session_id: str) -> dict[str, Any] | None:
        bundle = self.get_session(session_id)
        if not bundle:
            return None
        source_events = bundle["events"]
        events = [self._export_safe_event(event) for event in source_events]
        credentials, commands, payloads, iocs, mappings, enrichments = [], [], [], [], [], []
        for event in events:
            credential = event["observed"].get("credential")
            if isinstance(credential, dict):
                secret = self._credential_secret_summary(credential)
                credentials.append({
                    "event_id": event["id"],
                    "username": credential.get("username"),
                    "password_length": credential.get("password_length"),
                    "password_sha256": credential.get("password_sha256"),
                    "password_complete": credential.get("password_complete"),
                    "sensor_reported_password_length": credential.get("sensor_reported_password_length"),
                    "sensor_reported_password_sha256": credential.get("sensor_reported_password_sha256"),
                    "correlation_fingerprint": secret,
                })
            if event["observed"].get("command"):
                commands.append({"event_id": event["id"], "command": event["observed"]["command"]})
            if event["observed"].get("payload"):
                payloads.append({"event_id": event["id"], "payload": event["observed"]["payload"]})
            if event["enrichment"]:
                enrichments.append({"event_id": event["id"], "sources": event["enrichment"]})
            for ioc in event["derived"].get("ioc", []) or []:
                iocs.append({"event_id": event["id"], "ioc": ioc})
            for family in ("mitre", "cve"):
                for item in event["derived"].get(family, []) or []:
                    mappings.append({"event_id": event["id"], "family": family, "mapping": item})
        normalization_events = [
            event for event in events
            if isinstance((event.get("collector") or {}).get("normalization"), dict)
            and (event.get("collector") or {}).get("normalization", {}).get("lossy")
        ]
        truncated_normalization_events = [
            event for event in events
            if isinstance((event.get("collector") or {}).get("normalization"), dict)
            and (event.get("collector") or {}).get("normalization", {}).get("truncated")
        ]
        sensor_truncated_events = [
            event for event in events
            if isinstance((event.get("observed") or {}).get("sensor_capture"), dict)
            and (event.get("observed") or {}).get("sensor_capture", {}).get("truncated")
        ]
        sensor_rejected_events = [
            event for event in events
            if isinstance((event.get("observed") or {}).get("sensor_capture"), dict)
            and (event.get("observed") or {}).get("sensor_capture", {}).get("rejected")
        ]
        limitations = [
            "IP, ASN and geolocation do not establish human identity or attribution.",
            "External enrichment is contextual and may be stale or inaccurate.",
            "Derived MITRE/CVE entries are included only when rationale and evidence were stored with the event.",
            "Credential exports never include cleartext passwords, even when raw credential storage was explicitly enabled.",
            "collector_received_at is collector-controlled receipt metadata; event timestamp remains sensor-reported.",
            "Rows created before collector receipt tracking was introduced may have collector_received_at backfilled from the event timestamp.",
        ]
        if truncated_normalization_events:
            limitations.append(
                "One or more stored events contain explicitly disclosed field/collection truncation; inspect collector.normalization before treating payload text as complete."
            )
        if sensor_truncated_events:
            limitations.append(
                "One or more sensors captured only a bounded prefix of hostile input; inspect observed.sensor_capture before treating credentials, commands or payloads as complete."
            )
        if sensor_rejected_events:
            limitations.append(
                "One or more sensor inputs were rejected because a capture limit was exceeded; the rejection event proves the limit condition, not the full rejected content."
            )
        if bundle.get("analysis", {}).get("truncated"):
            limitations.append(
                "Session analysis was truncated to the configured latest-event limit; this report is not a complete retained-session timeline."
            )
        return {
            "report_type": "investigation_session",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analysis": bundle.get("analysis", {}),
            "session": bundle["session"],
            "summary": bundle["summary"],
            "facts": {
                "event_count": len(events),
                "events_with_lossy_normalization": len(normalization_events),
                "events_with_field_truncation": len(truncated_normalization_events),
                "events_with_sensor_truncation": len(sensor_truncated_events),
                "events_with_sensor_rejection": len(sensor_rejected_events),
                "event_types": sorted({event["event_type"] for event in events}),
                "source_ips": sorted({event["source_ip"] for event in events if event.get("source_ip")}),
                "services": sorted({event["service"] for event in events if event.get("service")}),
                "protocols": sorted({event["protocol"] for event in events if event.get("protocol")}),
                "destination_ports": sorted({
                    event["destination_port"] for event in events if event.get("destination_port")
                }),
                "sensor_first_timestamp": min((event["timestamp"] for event in events), default=None),
                "sensor_last_timestamp": max((event["timestamp"] for event in events), default=None),
                "collector_first_received": min(
                    (event["collector_received_at"] for event in events if event.get("collector_received_at")),
                    default=None,
                ),
                "collector_last_received": max(
                    (event["collector_received_at"] for event in events if event.get("collector_received_at")),
                    default=None,
                ),
            },
            "credentials": credentials,
            "commands": commands,
            "payloads": payloads,
            "enrichment": enrichments,
            "derived_iocs": iocs,
            "evidence_backed_mappings": mappings,
            "events": events,
            "limitations": limitations,
        }

    def relations(self, session_id: str) -> dict[str, Any]:
        bundle = self.get_session(session_id)
        if not bundle:
            return {"nodes": [], "edges": []}

        nodes: dict[str, dict[str, Any]] = {}
        edges: set[tuple[str, str, str]] = set()
        graph_truncated = False

        def add(kind: str, value: Any, provenance: str, metadata: dict[str, Any] | None = None) -> str | None:
            nonlocal graph_truncated
            if value in (None, ""):
                return None
            label = str(value)
            digest = hashlib.sha256(f"{kind}\0{label}".encode("utf-8", "replace")).hexdigest()[:20]
            node_id = f"{kind}:{digest}"
            if node_id not in nodes and len(nodes) >= self.relation_max_nodes:
                graph_truncated = True
                return None
            node = {
                "id": node_id,
                "kind": kind,
                "label": label[:180],
                "provenance": provenance,
            }
            if metadata:
                node["metadata"] = deepcopy(metadata)
            nodes[node_id] = node
            return node_id

        for event in bundle["events"]:
            event_node = add("event", event["id"], "observed")
            if event_node is None and graph_truncated:
                break
            summary = bundle.get("summary", {})
            session_node = add("session", event["session_id"], "derived", {
                "correlation": deepcopy(summary.get("correlation") or {
                    "method": summary.get("correlation_method", "temporal_fallback"),
                    "strength": "heuristic",
                    "basis": [],
                })
            })
            ip_node = add("ip", event.get("source_ip"), "observed")
            asn_node = add("asn", event.get("asn"), "enrichment")
            country_node = add("country", event.get("country"), "enrichment")
            port_node = add("port", event.get("destination_port"), "observed")
            protocol_node = add("protocol", event.get("protocol"), "observed")
            service_node = add("service", event.get("service"), "observed")
            honeypot_node = add("honeypot", event.get("honeypot"), "observed")
            credential = event["observed"].get("credential")
            credential = credential if isinstance(credential, dict) else {}
            user_node = add("credential", credential.get("username"), "observed")
            secret_node = None
            secret = self._credential_secret_summary(credential)
            if secret:
                secret_node = add(
                    "credential_secret_fingerprint",
                    secret["label"],
                    "derived",
                    {
                        "algorithm": "sha256",
                        "password_length": secret["length"],
                        "complete": secret["complete"],
                        "fingerprint_provenance": secret["provenance"],
                    },
                )
            command_node = add("command", event["observed"].get("command"), "observed")
            payload_node = add("payload", event["observed"].get("payload"), "observed")

            alert = event["observed"].get("alert")
            alert = alert if isinstance(alert, dict) else {}
            alert_node = add("ids", alert.get("signature"), "observed", {
                "category": alert.get("category"),
                "signature_id": alert.get("signature_id"),
            })

            for target, relation in [
                (session_node, "belongs_to"),
                (ip_node, "source"),
                (asn_node, "enriched_asn"),
                (country_node, "enriched_country"),
                (port_node, "targets_port"),
                (protocol_node, "uses_protocol"),
                (service_node, "targets_service"),
                (honeypot_node, "observed_by"),
                (user_node, "uses_username"),
                (secret_node, "credential_secret_fingerprint"),
                (command_node, "observed_command"),
                (payload_node, "observed_payload"),
                (alert_node, "ids_alert"),
            ]:
                if event_node and target:
                    edges.add((event_node, target, relation))

            for item in event["derived"].get("mitre", []) or []:
                if not isinstance(item, dict):
                    continue
                mitre_node = add("mitre", item.get("technique_id"), "derived", {
                    "rationale": item.get("rationale"),
                    "evidence": item.get("evidence"),
                })
                if event_node and mitre_node:
                    edges.add((event_node, mitre_node, "mapped_with_evidence"))

            for item in event["derived"].get("cve", []) or []:
                if not isinstance(item, dict):
                    continue
                cve_node = add("cve", item.get("cve_id"), "derived", {
                    "rationale": item.get("rationale"),
                    "evidence": item.get("evidence"),
                })
                if event_node and cve_node:
                    edges.add((event_node, cve_node, "correlated_with_evidence"))

            for ioc in event["derived"].get("ioc", []) or []:
                if not isinstance(ioc, dict):
                    continue
                ioc_type = ioc.get("type")
                ioc_value = ioc.get("value")
                ioc_node = add("ioc", ioc_value, "derived", {
                    "type": ioc_type,
                    "evidence": ioc.get("evidence"),
                    "classification": ioc.get("classification"),
                })
                if event_node and ioc_node:
                    edges.add((event_node, ioc_node, "derived_ioc"))

            threat_context = (event.get("enrichment") or {}).get("threat_context")
            if isinstance(threat_context, dict):
                source = threat_context.get("source")
                data = threat_context.get("data") if isinstance(threat_context.get("data"), dict) else {}
                for match in (data.get("matches") or [])[:16]:
                    if not isinstance(match, dict):
                        continue
                    kind = match.get("type")
                    value = match.get("value")
                    label = f"{kind}: {value}" if kind and value not in (None, "") else value
                    ti_node = add("threat_intel", label, "enrichment", {
                        "source": source,
                        "confidence": match.get("confidence"),
                        "labels": match.get("labels"),
                        "reference": match.get("reference"),
                        "evidence": match.get("evidence"),
                    })
                    if event_node and ti_node:
                        edges.add((event_node, ti_node, "external_threat_context"))

        graph_analysis = dict(bundle.get("analysis", {}))
        graph_analysis.update({
            "graph_truncated": graph_truncated,
            "graph_node_limit": self.relation_max_nodes,
            "graph_nodes_returned": len(nodes),
            "graph_edges_returned": len(edges),
        })
        return {
            "analysis": graph_analysis,
            "nodes": list(nodes.values()),
            "edges": [
                {"source": source, "target": target, "relation": relation}
                for source, target, relation in sorted(edges)
            ],
            "provenance": {
                "observed": "direct sensor or IDS telemetry",
                "enrichment": "external or operator-supplied context",
                "derived": "deterministic correlation or evidence-backed derivation",
            },
        }
