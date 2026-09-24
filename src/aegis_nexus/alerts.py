from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ALERT_STATUSES = {"new", "acknowledged", "investigating", "closed"}


class AlertStore:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    source_ip TEXT,
                    session_id TEXT,
                    status TEXT NOT NULL DEFAULT 'new',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_evidence (
                    alert_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    PRIMARY KEY(alert_id,evidence_type,evidence_id),
                    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS alert_tags (
                    alert_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY(alert_id,tag),
                    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS alert_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_queue ON alerts(status,severity,last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_rule_source ON alerts(rule_id,source_ip,status,last_seen DESC);
            """)

    def record(self, finding: dict[str, Any], event_timestamp: str) -> dict[str, Any]:
        now = self._now()
        source_ip = finding.get("source_ip")
        session_id = finding.get("session_id")
        with self.connect() as conn:
            existing = conn.execute(
                """
                SELECT id FROM alerts
                WHERE rule_id=? AND rule_version=?
                  AND COALESCE(source_ip,'')=COALESCE(?, '')
                  AND COALESCE(session_id,'')=COALESCE(?, '')
                  AND status!='closed'
                ORDER BY last_seen DESC LIMIT 1
                """,
                (finding["rule_id"], finding["rule_version"], source_ip, session_id),
            ).fetchone()
            if existing:
                alert_id = existing["id"]
                conn.execute(
                    "UPDATE alerts SET last_seen=?,occurrence_count=occurrence_count+1,updated_at=? WHERE id=?",
                    (event_timestamp, now, alert_id),
                )
            else:
                alert_id = "alert_" + uuid.uuid4().hex[:20]
                conn.execute(
                    """
                    INSERT INTO alerts(
                        id,schema_version,rule_id,rule_version,title,description,severity,confidence,
                        source_ip,session_id,status,first_seen,last_seen,occurrence_count,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?, 'new',?,?,1,?,?)
                    """,
                    (
                        alert_id, finding["schema_version"], finding["rule_id"], finding["rule_version"],
                        finding["title"], finding.get("description", ""), finding["severity"],
                        int(finding["confidence"]), source_ip, session_id, event_timestamp,
                        event_timestamp, now, now,
                    ),
                )
            for evidence in finding.get("evidence", [])[:128]:
                if not isinstance(evidence, dict):
                    continue
                evidence_type = str(evidence.get("type") or "")[:32]
                evidence_id = str(evidence.get("id") or "")[:128]
                if evidence_type and evidence_id:
                    conn.execute(
                        "INSERT OR IGNORE INTO alert_evidence(alert_id,evidence_type,evidence_id,added_at) VALUES(?,?,?,?)",
                        (alert_id, evidence_type, evidence_id, now),
                    )
        return self.get(alert_id) or {}

    def _hydrate(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evidence"] = [
            dict(r) for r in conn.execute(
                "SELECT evidence_type AS type,evidence_id AS id,added_at FROM alert_evidence WHERE alert_id=? ORDER BY added_at,id",
                (item["id"],),
            ).fetchall()
        ]
        item["tags"] = [
            r["tag"] for r in conn.execute(
                "SELECT tag FROM alert_tags WHERE alert_id=? ORDER BY tag COLLATE NOCASE", (item["id"],)
            ).fetchall()
        ]
        item["notes"] = [
            dict(r) for r in conn.execute(
                "SELECT id,body,created_at FROM alert_notes WHERE alert_id=? ORDER BY id", (item["id"],)
            ).fetchall()
        ]
        item["classification_provenance"] = "detection_rule"
        item["related_iocs"] = []
        item["related_session_ids"] = [item["session_id"]] if item.get("session_id") else []
        events_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()
        if events_table:
            event_ids = [entry["id"] for entry in item["evidence"] if entry.get("type") == "event"][:128]
            if event_ids:
                placeholders = ",".join("?" for _ in event_ids)
                rows = conn.execute(
                    f"SELECT id,session_id,derived FROM events WHERE id IN ({placeholders})",
                    event_ids,
                ).fetchall()
                seen_iocs: set[tuple[str, str]] = set()
                sessions = set(item["related_session_ids"])
                for event_row in rows:
                    if event_row["session_id"]:
                        sessions.add(str(event_row["session_id"]))
                    try:
                        derived = json.loads(event_row["derived"]) if event_row["derived"] else {}
                    except (TypeError, json.JSONDecodeError):
                        derived = {}
                    for ioc in derived.get("ioc", []) if isinstance(derived, dict) else []:
                        if not isinstance(ioc, dict):
                            continue
                        ioc_type = str(ioc.get("type") or "")[:64]
                        value = str(ioc.get("value") or "")[:512]
                        key = (ioc_type, value)
                        if not ioc_type or not value or key in seen_iocs:
                            continue
                        seen_iocs.add(key)
                        item["related_iocs"].append({
                            "type": ioc_type,
                            "value": value,
                            "evidence_event_id": event_row["id"],
                            "provenance": "derived",
                        })
                        if len(item["related_iocs"]) >= 128:
                            break
                    if len(item["related_iocs"]) >= 128:
                        break
                item["related_session_ids"] = sorted(sessions)
        return item

    def get(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id[:128],)).fetchone()
            return self._hydrate(conn, row) if row else None

    def list(self, limit: int = 100, status: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status=?")
            params.append(status[:32])
        if severity:
            clauses.append("severity=?")
            params.append(severity[:32])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(int(limit), 300)))
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts{where} ORDER BY last_seen DESC,id DESC LIMIT ?", params
            ).fetchall()
            return [self._hydrate(conn, row) for row in rows]

    def update(self, alert_id: str, *, status: str | None = None, tags: list[str] | None = None) -> dict[str, Any] | None:
        if status is not None and status not in ALERT_STATUSES:
            raise ValueError("invalid_alert_status")
        now = self._now()
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id[:128],)).fetchone():
                return None
            if status is not None:
                conn.execute("UPDATE alerts SET status=?,updated_at=? WHERE id=?", (status, now, alert_id[:128]))
            if tags is not None:
                conn.execute("DELETE FROM alert_tags WHERE alert_id=?", (alert_id[:128],))
                for tag in tags[:32]:
                    clean = str(tag).strip()[:64]
                    if clean:
                        conn.execute("INSERT OR IGNORE INTO alert_tags(alert_id,tag) VALUES(?,?)", (alert_id[:128], clean))
                conn.execute("UPDATE alerts SET updated_at=? WHERE id=?", (now, alert_id[:128]))
        return self.get(alert_id)

    def add_note(self, alert_id: str, body: str) -> dict[str, Any] | None:
        clean = str(body).strip()
        if not clean or len(clean) > 4000:
            raise ValueError("invalid_alert_note")
        now = self._now()
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id[:128],)).fetchone():
                return None
            count = conn.execute("SELECT COUNT(*) AS count FROM alert_notes WHERE alert_id=?", (alert_id[:128],)).fetchone()["count"]
            if int(count) >= 500:
                raise ValueError("alert_note_limit")
            conn.execute("INSERT INTO alert_notes(alert_id,body,created_at) VALUES(?,?,?)", (alert_id[:128], clean, now))
            conn.execute("UPDATE alerts SET updated_at=? WHERE id=?", (now, alert_id[:128]))
        return self.get(alert_id)
