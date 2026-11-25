"""Case-management storage domain for :class:`~aegis_nexus.store.Store`.

Extracted from ``store.py`` as an incremental Cycle I storage split (ADR 0003).
The analyst case workspace — create/read/update/delete, evidence links, notes,
history log, the case report and the case timeline — lives here as a mixin that
``Store`` composes, so the public API (``Store(...).create_case(...)`` etc.) and
its behaviour are unchanged (guarded by the case-workflow and API-contract
tests).

The mixin relies, through ``self``, on the composed ``Store`` for the shared
connection (``connect``), bounded limits (``max_cases``), the optional IOC
resolver (``_ioc_resolver``) and case pruning (``prune_cases``). It never widens
a trust boundary: evidence timestamps are taken as recorded (never re-derived),
IOC case-evidence is resolved only through the injected resolver, and every
mutation is written to the tamper-evident case history log.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any


class CaseStoreMixin:
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
                INSERT INTO cases(id,title,status,severity,priority,owner,summary,conclusion,hypotheses,created_at,updated_at,closed_at)
                SELECT ?,?,?,?,?,?,?,?,?,?,?,?
                WHERE (SELECT COUNT(*) FROM cases) < ?
                """,
                (
                    case_id,
                    data["title"],
                    data["status"],
                    data["severity"],
                    data.get("priority", "normal"),
                    data.get("owner", ""),
                    data["summary"],
                    data.get("conclusion", ""),
                    data.get("hypotheses", ""),
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

    def set_ioc_resolver(self, resolver: Callable[[str], dict[str, Any] | None] | None) -> None:
        """Inject the derived-IOC resolver (the IOC workspace's ``get``)."""
        self._ioc_resolver = resolver

    def _resolve_case_evidence(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        evidence_type = item["evidence_type"]
        evidence_id = item["evidence_id"]
        item["available"] = False
        item["summary"] = None
        if evidence_type == "ioc":
            # IOC are derived artifacts, resolved on the fly by the injected
            # resolver; availability means the artifact is still derivable from
            # retained events, never a threat-intelligence verdict.
            resolver = self._ioc_resolver
            if resolver is not None:
                try:
                    ioc = resolver(evidence_id)
                except Exception:
                    ioc = None
                if ioc:
                    item["available"] = True
                    item["summary"] = {
                        "id": ioc.get("id"),
                        "type": ioc.get("type"),
                        "value": ioc.get("value"),
                        "classification": ioc.get("classification"),
                        "first_seen": ioc.get("first_seen"),
                        "last_seen": ioc.get("last_seen"),
                        "occurrences": ioc.get("occurrences"),
                        "evidence_provenance": "derived_artifact",
                    }
            return item
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
        elif evidence_type == "alert":
            alert = conn.execute(
                """
                SELECT id,rule_id,rule_version,title,severity,confidence,source_ip,session_id,
                       status,first_seen,last_seen,occurrence_count
                FROM alerts WHERE id=?
                """,
                (evidence_id,),
            ).fetchone()
            if alert:
                item["available"] = True
                item["summary"] = dict(alert)
                item["summary"]["classification_provenance"] = "detection_rule"
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
            for key in ("title", "summary", "status", "severity", "priority", "owner", "conclusion", "hypotheses"):
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
        # Derived IOC existence is validated up front via the injected resolver
        # (read-only, its own connection) so we never open a nested write path.
        ioc_available = None
        if evidence_type == "ioc":
            resolver = self._ioc_resolver
            if resolver is not None:
                try:
                    ioc_available = resolver(evidence_id)
                except Exception:
                    ioc_available = None
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
            elif evidence_type == "session":
                available = conn.execute("SELECT 1 FROM sessions WHERE id=?", (evidence_id,)).fetchone()
            elif evidence_type == "alert":
                available = conn.execute("SELECT 1 FROM alerts WHERE id=?", (evidence_id,)).fetchone()
            elif evidence_type == "ioc":
                available = ioc_available
            else:
                available = None
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
                "priority": case.get("priority"),
                "owner": case.get("owner"),
                "summary": case["summary"],
                "conclusion": case.get("conclusion", ""),
                "hypotheses": case.get("hypotheses", ""),
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
    def _evidence_observed_timestamp(evidence: dict[str, Any]) -> str | None:
        summary = evidence.get("summary")
        if not isinstance(summary, dict):
            return None
        for key in ("timestamp", "first_seen", "started_at"):
            value = summary.get(key)
            if value:
                return str(value)
        return None

    def case_timeline(self, case_id: str) -> dict[str, Any] | None:
        """Unified, chronologically ordered case timeline.

        Merges investigation actions (case lifecycle history, notes and
        evidence links — analyst/collector provenance) with the observed,
        sensor-reported timestamp of each referenced piece of evidence
        (observed provenance). Timestamps are never re-derived or inferred; the
        two provenance classes stay labelled and distinct.
        """
        case = self.get_case(case_id)
        if case is None:
            return None
        entries: list[dict[str, Any]] = []
        for item in case.get("history", []):
            entries.append({
                "timestamp": item.get("timestamp"),
                "kind": "case." + str(item.get("action") or "event"),
                "provenance": "analyst",
                "detail": item.get("detail") or {},
            })
        for note in case.get("notes", []):
            entries.append({
                "timestamp": note.get("created_at"),
                "kind": "note.added",
                "provenance": "analyst",
                "detail": {"note_id": note.get("id")},
            })
        for evidence in case.get("evidence", []):
            ref = {"evidence_type": evidence.get("evidence_type"), "evidence_id": evidence.get("evidence_id")}
            entries.append({
                "timestamp": evidence.get("added_at"),
                "kind": "evidence.linked",
                "provenance": "analyst",
                "detail": ref,
            })
            observed = self._evidence_observed_timestamp(evidence)
            if observed:
                entries.append({
                    "timestamp": observed,
                    "kind": "evidence.observed",
                    "provenance": "observed",
                    "detail": ref,
                })
        entries = [entry for entry in entries if entry.get("timestamp")]
        entries.sort(key=lambda entry: str(entry["timestamp"]))
        return {
            "case_id": case_id,
            "schema_version": "1.0",
            "entry_count": len(entries),
            "entries": entries[:1000],
            "provenance_note": (
                "observed = sensor-reported evidence time; analyst = investigation "
                "actions on the case. Timestamps are taken as recorded, never "
                "re-derived or inferred."
            ),
        }
