"""Append-only operator audit log.

Every operator action that changes investigation state or releases evidence —
alert lifecycle changes, case changes, exports and PCAP/artifact access — is
recorded here, attributed to the authenticated operator identity (Cycle P).

Design constraints:

* **Append-only.** Rows are never edited in place; a ``BEFORE UPDATE`` trigger
  (see :mod:`aegis_nexus.migrations`) rejects any attempt. The only deletions
  are bounded, oldest-first retention prunes, which are themselves recorded as
  an ``audit.retention_prune`` entry so the loss is explicit, never silent.
* **Attribution, not content.** The log stores *who did what to which entity*,
  plus small structured metadata (e.g. the new alert status). It never copies
  attacker-controlled payloads or operator free-text note bodies, keeping the
  trail useful without duplicating personal data or hostile input.
* **Hostile-input safe.** Operator-supplied values (target identifiers, detail
  fields) are treated as untrusted: control characters are stripped and every
  string, key count and the serialized detail are bounded.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .migrations import apply_migrations, enable_wal

# Actions are code constants, so they are validated strictly: an unknown action
# is a programming error, not hostile input.
ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

MAX_OPERATOR_LEN = 64
MAX_ACTION_LEN = 64
MAX_TARGET_TYPE_LEN = 64
MAX_TARGET_ID_LEN = 128
MAX_OUTCOME_LEN = 16
MAX_DETAIL_KEYS = 32
MAX_DETAIL_VALUE_LEN = 256
MAX_DETAIL_LIST_ITEMS = 32
MAX_DETAIL_BYTES = 4000

# Retention defaults: the audit trail should outlive telemetry, so it keeps a
# full year and a generous row ceiling by default. ``0`` disables either bound.
DEFAULT_RETENTION_DAYS = 365
DEFAULT_MAX_ROWS = 1_000_000

VALID_OUTCOMES = ("success", "denied", "error")


class OperatorAuditError(ValueError):
    pass


def _strip_control(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def _sanitize_scalar(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    text = _strip_control(str(value))
    return text[:MAX_DETAIL_VALUE_LEN]


def _sanitize_detail(detail: Any) -> dict[str, Any]:
    """Bound an operator-supplied detail mapping to small, safe, structured data."""
    if not isinstance(detail, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in list(detail.items())[:MAX_DETAIL_KEYS]:
        if not isinstance(key, str):
            continue
        safe_key = _strip_control(key)[:64]
        if not safe_key:
            continue
        if isinstance(value, list):
            clean[safe_key] = [_sanitize_scalar(item) for item in value[:MAX_DETAIL_LIST_ITEMS]]
        else:
            clean[safe_key] = _sanitize_scalar(value)
    encoded = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_DETAIL_BYTES:
        # The caller passed more structured data than the trail stores; keep the
        # fact that it was truncated rather than a partial, misleading record.
        return {"truncated": True}
    return clean


class OperatorAuditLog:
    def __init__(
        self,
        path: str,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_rows: int = DEFAULT_MAX_ROWS,
    ):
        self.path = path
        self.retention_days = max(0, int(retention_days))
        self.max_rows = max(0, int(max_rows))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            apply_migrations(conn)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        enable_wal(conn)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    def record(
        self,
        operator: str,
        action: str,
        *,
        target_type: str = "",
        target_id: str = "",
        detail: dict[str, Any] | None = None,
        source_ip: str | None = None,
        outcome: str = "success",
    ) -> dict[str, Any]:
        clean_action = str(action or "").strip().lower()[:MAX_ACTION_LEN]
        if not ACTION_PATTERN.fullmatch(clean_action):
            raise OperatorAuditError(f"invalid audit action: {action!r}")
        clean_operator = _strip_control(str(operator or "").strip())[:MAX_OPERATOR_LEN] or "unknown"
        clean_target_type = _strip_control(str(target_type or "").strip())[:MAX_TARGET_TYPE_LEN]
        clean_target_id = _strip_control(str(target_id or "").strip())[:MAX_TARGET_ID_LEN]
        clean_outcome = str(outcome or "success").strip().lower()[:MAX_OUTCOME_LEN]
        if clean_outcome not in VALID_OUTCOMES:
            clean_outcome = "success"
        clean_source = None
        if source_ip:
            try:
                clean_source = str(ipaddress.ip_address(str(source_ip)))
            except ValueError:
                clean_source = None
        encoded_detail = json.dumps(
            _sanitize_detail(detail or {}),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        now = self._iso(self._now())
        with self.connect() as conn:
            row_id = self._insert(
                conn,
                timestamp=now,
                operator=clean_operator,
                action=clean_action,
                target_type=clean_target_type,
                target_id=clean_target_id,
                outcome=clean_outcome,
                source_ip=clean_source,
                detail=encoded_detail,
            )
            self._enforce_retention(conn)
        return {
            "id": row_id,
            "timestamp": now,
            "operator": clean_operator,
            "action": clean_action,
            "target_type": clean_target_type,
            "target_id": clean_target_id,
            "outcome": clean_outcome,
            "source_ip": clean_source,
            "detail": json.loads(encoded_detail),
        }

    @staticmethod
    def _insert(
        conn: sqlite3.Connection,
        *,
        timestamp: str,
        operator: str,
        action: str,
        target_type: str,
        target_id: str,
        outcome: str,
        source_ip: str | None,
        detail: str,
    ) -> int:
        cursor = conn.execute(
            """
            INSERT INTO operator_audit_log(
                timestamp,operator,action,target_type,target_id,outcome,source_ip,detail
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (timestamp, operator, action, target_type, target_id, outcome, source_ip, detail),
        )
        return int(cursor.lastrowid)

    def _enforce_retention(self, conn: sqlite3.Connection) -> None:
        """Prune oldest entries beyond the age/row bounds and record the loss."""
        pruned = 0
        if self.retention_days > 0:
            cutoff = self._iso(self._now() - timedelta(days=self.retention_days))
            pruned += conn.execute(
                "DELETE FROM operator_audit_log WHERE timestamp < ? AND action != 'audit.retention_prune'",
                (cutoff,),
            ).rowcount or 0
        if self.max_rows > 0:
            total = int(conn.execute("SELECT COUNT(*) FROM operator_audit_log").fetchone()[0])
            overflow = total - self.max_rows
            if overflow > 0:
                pruned += conn.execute(
                    """
                    DELETE FROM operator_audit_log WHERE id IN (
                        SELECT id FROM operator_audit_log ORDER BY id ASC LIMIT ?
                    )
                    """,
                    (overflow,),
                ).rowcount or 0
        if pruned > 0:
            # Record the drop as evidence loss. This entry is itself exempt from
            # the age prune above so the record of a prune is never pruned away
            # in the same pass, and it does not recurse into retention.
            self._insert(
                conn,
                timestamp=self._iso(self._now()),
                operator="system",
                action="audit.retention_prune",
                target_type="operator_audit_log",
                target_id="",
                outcome="success",
                source_ip=None,
                detail=json.dumps(
                    {"pruned": int(pruned)}, sort_keys=True, separators=(",", ":")
                ),
            )

    def list(
        self,
        *,
        limit: int = 200,
        operator: str | None = None,
        action: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if operator:
            clauses.append("operator = ?")
            params.append(_strip_control(str(operator).strip())[:MAX_OPERATOR_LEN])
        if action:
            clauses.append("action = ?")
            params.append(str(action).strip().lower()[:MAX_ACTION_LEN])
        if target_type:
            clauses.append("target_type = ?")
            params.append(_strip_control(str(target_type).strip())[:MAX_TARGET_TYPE_LEN])
        if target_id:
            clauses.append("target_id = ?")
            params.append(_strip_control(str(target_id).strip())[:MAX_TARGET_ID_LEN])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id,timestamp,operator,action,target_type,target_id,outcome,source_ip,detail
                FROM operator_audit_log {where}
                ORDER BY id DESC LIMIT ?
                """,
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["detail"] = json.loads(item["detail"])
            except (TypeError, json.JSONDecodeError):
                item["detail"] = {}
            result.append(item)
        return result

    def count(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM operator_audit_log").fetchone()[0])
