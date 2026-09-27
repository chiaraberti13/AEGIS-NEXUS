from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .detection_config import RULE_DEFAULTS
from .migrations import apply_migrations, enable_wal


MAX_SUPPRESSION_SECONDS = 30 * 24 * 60 * 60


class SuppressionValidationError(ValueError):
    pass


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SuppressionValidationError("invalid_expiry") from exc
    if parsed.tzinfo is None:
        raise SuppressionValidationError("expiry_timezone_required")
    return parsed.astimezone(timezone.utc)


class DetectionSuppressionStore:
    def __init__(self, path: str):
        self.path = path
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

    def create(
        self,
        *,
        rule_id: str,
        owner: str,
        reason: str,
        expires_at: str,
        source_ip: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        rule = str(rule_id or "").strip()
        clean_owner = str(owner or "").strip()
        clean_reason = str(reason or "").strip()
        clean_source = str(source_ip or "").strip() or None
        if rule not in RULE_DEFAULTS:
            raise SuppressionValidationError("unknown_detection_rule")
        if not clean_owner or len(clean_owner) > 128:
            raise SuppressionValidationError("invalid_owner")
        if not clean_reason or len(clean_reason) > 1000:
            raise SuppressionValidationError("invalid_reason")
        if clean_source:
            try:
                clean_source = str(ipaddress.ip_address(clean_source))
            except ValueError as exc:
                raise SuppressionValidationError("invalid_source_ip") from exc
        now = self._now()
        expiry = _parse_utc(expires_at)
        if expiry <= now:
            raise SuppressionValidationError("expiry_must_be_future")
        if expiry - now > timedelta(seconds=MAX_SUPPRESSION_SECONDS):
            raise SuppressionValidationError("expiry_exceeds_30_days")
        suppression_id = "supp_" + uuid.uuid4().hex[:20]
        created_at = self._iso(now)
        actor_name = str(actor or clean_owner).strip()[:128] or clean_owner
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO detection_suppressions(id,rule_id,source_ip,owner,reason,created_at,expires_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (suppression_id, rule, clean_source, clean_owner, clean_reason, created_at, self._iso(expiry)),
            )
            conn.execute(
                """
                INSERT INTO detection_suppression_audit(suppression_id,action,actor,timestamp,detail)
                VALUES(?,?,?,?,?)
                """,
                (
                    suppression_id,
                    "created",
                    actor_name,
                    created_at,
                    json.dumps(
                        {"rule_id": rule, "source_ip": clean_source, "expires_at": self._iso(expiry)},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
        return self.get(suppression_id) or {}

    def get(self, suppression_id: str) -> dict[str, Any] | None:
        now = self._iso(self._now())
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_suppressions WHERE id=?",
                (suppression_id[:128],),
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            item["active"] = item["expires_at"] > now
            return item

    def list(self, *, active_only: bool = False, limit: int = 200) -> list[dict[str, Any]]:
        now = self._iso(self._now())
        where = "WHERE expires_at>?" if active_only else ""
        params: list[Any] = [now] if active_only else []
        params.append(max(1, min(int(limit), 500)))
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM detection_suppressions {where} ORDER BY expires_at DESC,id DESC LIMIT ?",
                params,
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["active"] = item["expires_at"] > now
        return items

    def audit(self, *, suppression_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        params: list[Any] = []
        where = ""
        if suppression_id:
            where = "WHERE suppression_id=?"
            params.append(suppression_id[:128])
        params.append(max(1, min(int(limit), 1000)))
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id,suppression_id,action,actor,timestamp,detail
                FROM detection_suppression_audit {where}
                ORDER BY timestamp DESC,id DESC LIMIT ?
                """,
                params,
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

    def delete(self, suppression_id: str, *, actor: str) -> bool:
        clean_actor = str(actor or "").strip()
        if not clean_actor or len(clean_actor) > 128:
            raise SuppressionValidationError("invalid_actor")
        now = self._iso(self._now())
        with self.connect() as conn:
            row = conn.execute(
                "SELECT rule_id,source_ip,expires_at FROM detection_suppressions WHERE id=?",
                (suppression_id[:128],),
            ).fetchone()
            if not row:
                return False
            conn.execute(
                """
                INSERT INTO detection_suppression_audit(suppression_id,action,actor,timestamp,detail)
                VALUES(?,?,?,?,?)
                """,
                (
                    suppression_id[:128],
                    "deleted",
                    clean_actor,
                    now,
                    json.dumps(dict(row), sort_keys=True, separators=(",", ":")),
                ),
            )
            conn.execute("DELETE FROM detection_suppressions WHERE id=?", (suppression_id[:128],))
        return True

    def match(self, finding: dict[str, Any], *, at: datetime | None = None) -> dict[str, Any] | None:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id not in RULE_DEFAULTS:
            return None
        source_ip = str(finding.get("source_ip") or "")
        now = self._iso(at or self._now())
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM detection_suppressions
                WHERE rule_id=? AND expires_at>?
                  AND (source_ip IS NULL OR source_ip='')
                  OR (rule_id=? AND expires_at>? AND source_ip=?)
                ORDER BY CASE WHEN source_ip IS NULL OR source_ip='' THEN 1 ELSE 0 END,
                         expires_at ASC,id ASC
                LIMIT 1
                """,
                (rule_id, now, rule_id, now, source_ip),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["active"] = True
        return item
