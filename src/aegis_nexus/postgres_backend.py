"""Optional PostgreSQL storage backend (Cycle H / ADR 0002).

A concrete :class:`~aegis_nexus.storage_backend.StorageBackend` implementation
backed by PostgreSQL (via psycopg 3). SQLite ``Store`` stays the default
reference backend; this backend is opt-in (`pip install '.[postgres]'`).

Scope — the **full StorageBackend contract**, every method verified by the
behavioural compatibility suite (`tests/test_backend_compatibility.py`) against
a real PostgreSQL:

- event ingest + fetch (full event JSON in a ``jsonb`` column, provenance
  classes preserved), bounded recent-event paging, filter options;
- collector counters, operator cases (CRUD + list + retention prune + evidence
  references, report and timeline), sensor heartbeats, sensor nonce anti-replay;
- detection and behavioural context windows, sensor telemetry/health rollups;
- operational health and a dashboard rollup computed in SQL.

A few capabilities stay SQLite-only because the PG core backend intentionally
does not model those domains: per-sensor event *sequencing* (PG reports sensors
unsequenced), and ``session``/``alert`` *case evidence* kinds (no sessions/alerts
tables here, so such references cannot be verified and are refused/unavailable,
never faked). These are honestly reported, not silent wrong answers. The
:class:`PostgresBackendUnsupported` exception is retained as a stable symbol for
any future deferral but is no longer raised. Extensions are tracked by ADR 0002.

Security/invariants: parameterized SQL only (no string interpolation of
values); the event document is stored and returned as-is, so the four
provenance classes are never collapsed; credentials are already redacted by
``normalize_event`` upstream, so nothing extra is persisted here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .migrations import SchemaVersionError
from .pagination import decode_cursor, encode_cursor
from .storage_backend import REQUIRED_METHODS


class PostgresBackendUnsupported(NotImplementedError):
    """Raised for StorageBackend methods not implemented by the core PG backend."""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_anchor(raw: str) -> datetime | None:
    try:
        anchor = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    return anchor.astimezone(timezone.utc)


_BASELINE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    collector_received_at TEXT NOT NULL,
    honeypot TEXT,
    event_type TEXT,
    severity TEXT,
    source_ip TEXT,
    session_id TEXT,
    document JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_received_idx ON events (collector_received_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS events_severity_idx ON events (severity);
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    status TEXT,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    sensor_id TEXT PRIMARY KEY,
    last_seen_at TEXT NOT NULL,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS sensor_nonces (
    sensor_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (sensor_id, nonce)
);
"""

# v2 — richer case schema: evidence references and lifecycle history as their
# own tables (mirroring the SQLite `case_evidence` / `case_history` tables in
# migrations.py), so case evidence/report/timeline can be served without
# collapsing their provenance into the case document JSONB. Tags stay in the
# case `document` (unlike SQLite's `case_tags`), and analyst notes are an
# SQLite-only Store extension (no `add_case_note` in the StorageBackend
# contract), so `case_notes` is intentionally not created here. ON DELETE
# CASCADE lets `delete_case` drop a case's children in one statement.
_CASE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS case_evidence (
    id BIGSERIAL PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE (case_id, evidence_type, evidence_id)
);
CREATE INDEX IF NOT EXISTS case_evidence_case_idx ON case_evidence (case_id);
CREATE TABLE IF NOT EXISTS case_history (
    id BIGSERIAL PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    detail JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS case_history_case_idx ON case_history (case_id);
"""


# Forward-only PostgreSQL migrations, mirroring the SQLite strategy
# (migrations.py): a transactional `schema_migrations` ledger replaces SQLite's
# PRAGMA user_version. Append a new (version, name, sql) tuple to evolve the
# schema; never edit or reorder a released migration. Each step runs in its own
# transaction under a session advisory lock, so concurrent workers re-read the
# version under the lock and never apply a step twice; a database written by a
# newer release is refused, not migrated down.
_PG_MIGRATIONS: tuple[tuple[int, str, str], ...] = (
    (1, "baseline", _BASELINE_SQL),
    (2, "case_schema", _CASE_SCHEMA_SQL),
)
POSTGRES_SCHEMA_VERSION = _PG_MIGRATIONS[-1][0]
_PG_ADVISORY_LOCK = 0x41454753  # "AEGS" — namespaced lock id for PG migrations

_LEDGER_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""


def _schema_version(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.schema_migrations') IS NOT NULL AS present")
        if not cur.fetchone()["present"]:
            return 0
        cur.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
        return int(cur.fetchone()["v"])


def apply_pg_migrations(conn) -> list[int]:
    """Bring a PostgreSQL database to the latest schema version; return applied versions.

    Forward-only and idempotent: already-applied steps are skipped. A database
    whose version exceeds the latest known migration is refused with
    SchemaVersionError rather than modified.
    """
    with conn.cursor() as cur:
        cur.execute(_LEDGER_SQL)
    latest = _PG_MIGRATIONS[-1][0]
    current = _schema_version(conn)
    if current > latest:
        raise SchemaVersionError(
            f"PostgreSQL schema version {current} is newer than supported version {latest}; "
            "upgrade AEGIS-NEXUS or point at a compatible database"
        )
    applied: list[int] = []
    for version, name, sql in _PG_MIGRATIONS:
        if version <= current:
            continue
        with conn.transaction():
            with conn.cursor() as cur:
                # Take the write lock first, then re-read the version under it so
                # concurrent workers never apply the same step twice.
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_PG_ADVISORY_LOCK,))
                cur.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
                if int(cur.fetchone()["v"]) >= version:
                    continue
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) VALUES (%s, %s, %s)",
                    (version, name, _utc_iso()),
                )
        applied.append(version)
    return applied


class PostgresBackend:
    """PostgreSQL-backed core persistence implementing the StorageBackend contract."""

    def __init__(self, dsn: str, *, max_cases: int = 10_000, case_retention_days: int = 0) -> None:
        import psycopg  # lazy: only required when this backend is actually used
        from psycopg.rows import dict_row

        self._psycopg = psycopg
        self.max_cases = max(1, min(int(max_cases), 1_000_000))
        self.case_retention_days = max(0, min(int(case_retention_days), 3650))
        self.analytics_max_events = 20_000
        self._ioc_resolver: Callable[[str], dict[str, Any] | None] | None = None
        self._conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
        self._init_schema()

    # -- lifecycle ---------------------------------------------------------
    def _init_schema(self) -> None:
        # Versioned, forward-only migrations with a transactional ledger.
        self.schema_version_applied = apply_pg_migrations(self._conn)
        from .store import COLLECTOR_COUNTERS
        with self._conn.cursor() as cur:
            for name in COLLECTOR_COUNTERS:
                cur.execute(
                    "INSERT INTO counters(name, value) VALUES (%s, 0) ON CONFLICT (name) DO NOTHING",
                    (name,),
                )

    def schema_version(self) -> int:
        """Current applied PostgreSQL schema version (0 on a fresh database)."""
        return _schema_version(self._conn)

    def close(self) -> None:
        self._conn.close()

    def verify_event_chain(self) -> dict[str, Any]:
        """Report that the tamper-evident event hash chain is a SQLite-only feature.

        The hash chain (``chain_seq``/``prev_hash``/``record_hash`` plus the
        ``event_chain_head`` anchor) is implemented only by the reference SQLite
        :class:`~aegis_nexus.store.Store`; ADR 0002 defers porting it, so this
        backend stores no chain. Rather than omitting the method — which would
        make a caller that iterates backends ``AttributeError`` or silently skip
        the integrity check — we answer explicitly and honestly: ``ok`` is
        ``False`` and ``supported`` is ``False`` so no caller can mistake the
        absence of a chain for a verified-intact one. Event tamper-evidence on
        PostgreSQL requires database-level controls (WAL archiving, restricted
        roles, append-only auditing), tracked by ADR 0002.
        """
        return {
            "backend": "postgresql",
            "supported": False,
            "ok": False,
            "records_verified": 0,
            "reason": "event hash chain is a SQLite-only capability (ADR 0002)",
        }

    # -- events ------------------------------------------------------------
    def ingest(self, event: dict[str, Any], collector_received_at: str | None = None) -> dict[str, Any]:
        from psycopg.types.json import Jsonb
        received_at = collector_received_at or _utc_iso()
        observed = event.get("observed") or {}
        # Simplified correlation: the sensor-provided session id when present,
        # else a stable (honeypot, source_ip) key. The rich temporal
        # correlation Store performs is intentionally out of scope here.
        session_id = str(
            observed.get("sensor_session_id")
            or f"{event.get('honeypot', 'unknown')}:{observed.get('source_ip', 'unknown')}"
        )
        stored = {**event, "session_id": session_id,
                  "received_at": received_at, "collector_received_at": received_at}
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO events (id, timestamp, collector_received_at, honeypot,
                       event_type, severity, source_ip, session_id, document)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO NOTHING""",
                (event["id"], event.get("timestamp"), received_at, event.get("honeypot"),
                 event.get("event_type"), event.get("severity"), observed.get("source_ip"),
                 session_id, Jsonb(stored)),
            )
        return stored

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT document FROM events WHERE id = %s", (event_id,))
            row = cur.fetchone()
        return row["document"] if row else None

    # Event filters supported directly as persisted columns. Enrichment-derived
    # filters (country/asn) and raw-observed ones (protocol/service/
    # destination_port) are matched from the jsonb document in filter_options;
    # page_events filters only on the indexed persisted columns.
    _PAGE_FILTER_COLUMNS = ("honeypot", "event_type", "severity", "source_ip", "session_id")

    def page_events(self, limit: int = 100, q: str | None = None,
                    filters: dict[str, str] | None = None, hours: int | None = None,
                    cursor: str | None = None, scope: str = "") -> dict[str, Any]:
        bounded = max(1, min(int(limit), 500))
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in (filters or {}).items():
            if value and key in self._PAGE_FILTER_COLUMNS:
                clauses.append(f"{key} = %s")
                params.append(value)
        since: str | None = None
        cursor_data: dict[str, Any] | None = None
        if cursor:
            cursor_data = decode_cursor(cursor, kind="events", scope=scope)
            since = cursor_data.get("since")
        elif hours is not None:
            bounded_hours = max(1, min(int(hours), 720))
            since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        if since:
            clauses.append("timestamp >= %s")
            params.append(since)
        if q:
            # The event document never holds cleartext credentials (normalize_event
            # redacts them upstream), so a document-wide text match is safe.
            clauses.append("(source_ip ILIKE %s OR event_type ILIKE %s OR honeypot ILIKE %s "
                           "OR document::text ILIKE %s)")
            needle = f"%{q[:128]}%"
            params.extend([needle] * 4)
        if cursor_data:
            clauses.append("(timestamp < %s OR (timestamp = %s AND id < %s))")
            params.extend([cursor_data["position"], cursor_data["position"], cursor_data["id"]])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(bounded + 1)
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT id, timestamp, document FROM events{where} "
                "ORDER BY timestamp DESC, id DESC LIMIT %s",
                tuple(params),
            )
            rows = cur.fetchall()
        has_more = len(rows) > bounded
        rows = rows[:bounded]
        items = [r["document"] for r in rows]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = encode_cursor(
                "events", position=str(last["timestamp"]), row_id=str(last["id"]),
                scope=scope, since=since,
            )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def detection_context(self, event: dict[str, Any], *, lookback_hours: int = 24,
                           source_limit: int = 1000, credential_limit: int = 250) -> list[dict[str, Any]]:
        """Bounded historical evidence for deterministic detection rules.

        Window anchored to the event timestamp (deterministic for replays).
        Matches same-source-IP events and same credential fingerprint events;
        raw secrets are never queried or returned (fingerprints only).
        """
        source_ip = str(event.get("source_ip") or (event.get("observed") or {}).get("source_ip") or "")
        anchor = _parse_anchor(str(event.get("timestamp") or ""))
        if anchor is None:
            return [event]
        bounded_hours = max(1, min(int(lookback_hours), 168))
        since = (anchor - timedelta(hours=bounded_hours)).isoformat()
        until = anchor.isoformat()
        items: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            if source_ip:
                cur.execute(
                    "SELECT document FROM events WHERE source_ip = %s AND timestamp >= %s "
                    "AND timestamp <= %s ORDER BY timestamp DESC, id DESC LIMIT %s",
                    (source_ip[:128], since, until, max(1, min(int(source_limit), 2000))),
                )
                items.extend(r["document"] for r in cur.fetchall())
            observed = event.get("observed") if isinstance(event.get("observed"), dict) else {}
            credential = observed.get("credential") if isinstance(observed.get("credential"), dict) else {}
            if credential.get("password_complete") is False:
                fingerprint = str(credential.get("sensor_reported_password_sha256") or "")
            else:
                fingerprint = str(credential.get("password_sha256") or "")
            if fingerprint:
                cur.execute(
                    "SELECT document FROM events WHERE timestamp >= %s AND timestamp <= %s AND COALESCE("
                    "CASE WHEN (document->'observed'->'credential'->>'password_complete') = 'false' "
                    "THEN document->'observed'->'credential'->>'sensor_reported_password_sha256' "
                    "ELSE document->'observed'->'credential'->>'password_sha256' END, '') = %s "
                    "ORDER BY timestamp DESC, id DESC LIMIT %s",
                    (since, until, fingerprint[:128], max(1, min(int(credential_limit), 1000))),
                )
                items.extend(r["document"] for r in cur.fetchall())
        by_id: dict[str, dict[str, Any]] = {}
        for item in items:
            event_id = str(item.get("id") or "")
            if event_id:
                by_id[event_id] = item
        current_id = str(event.get("id") or "")
        if current_id:
            by_id[current_id] = event
        return list(by_id.values())

    def behavioral_context(self, event: dict[str, Any], *, days: int = 30,
                           limit: int | None = None) -> dict[str, Any]:
        """Bounded historical baseline ending at the event timestamp, excluding the anchor."""
        anchor = _parse_anchor(str(event.get("timestamp") or "")) or datetime.now(timezone.utc)
        bounded_days = max(1, min(int(days), 30))
        cutoff = (anchor - timedelta(days=bounded_days)).isoformat()
        bounded_limit = max(100, min(int(limit or self.analytics_max_events), self.analytics_max_events))
        event_id = str(event.get("id") or "")
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT document FROM events WHERE timestamp >= %s AND timestamp <= %s AND id <> %s "
                "ORDER BY timestamp DESC, id DESC LIMIT %s",
                (cutoff, anchor.isoformat(), event_id, bounded_limit + 1),
            )
            rows = cur.fetchall()
        truncated = len(rows) > bounded_limit
        selected = rows[:bounded_limit]
        selected.reverse()
        return {
            "events": [r["document"] for r in selected],
            "analysis": {
                "anchor_event_id": event_id,
                "anchor_timestamp": anchor.isoformat(),
                "window_days": bounded_days,
                "event_limit": bounded_limit,
                "truncated": truncated,
                "scope": "historical_events_excluding_anchor",
            },
        }

    # -- counters ----------------------------------------------------------
    def counters(self) -> dict[str, int]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT name, value FROM counters")
            return {r["name"]: int(r["value"]) for r in cur.fetchall()}

    def increment_counter(self, name: str, by: int = 1) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO counters(name, value) VALUES (%s, %s)
                   ON CONFLICT (name) DO UPDATE SET value = counters.value + EXCLUDED.value""",
                (str(name), int(by)),
            )

    # -- cases -------------------------------------------------------------
    # The case "document" JSONB holds only the analyst-authored core fields
    # (title/status/severity/tags/…). Evidence references and lifecycle history
    # live in their own tables (migration v2) and are assembled into the view by
    # get_case, exactly as the SQLite Store joins its child tables — so the raw
    # document is never polluted with resolved evidence/history copies.
    def _case_doc(self, case_id: str) -> dict[str, Any] | None:
        """Raw stored case document (core fields only), or None if absent."""
        with self._conn.cursor() as cur:
            cur.execute("SELECT document FROM cases WHERE id = %s", (case_id,))
            row = cur.fetchone()
        return dict(row["document"]) if row else None

    def _case_log(self, case_id: str, action: str, detail: dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO case_history(case_id, timestamp, action, detail) VALUES (%s,%s,%s,%s)",
                (case_id, _utc_iso(), action[:64], Jsonb(detail)),
            )

    def _case_history(self, case_id: str) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, timestamp, action, detail FROM case_history "
                "WHERE case_id = %s ORDER BY id ASC LIMIT 500",
                (case_id,),
            )
            # psycopg returns JSONB as a Python object already; default to {}.
            return [
                {**dict(r), "detail": r["detail"] if isinstance(r["detail"], dict) else {}}
                for r in cur.fetchall()
            ]

    def create_case(self, data: dict[str, Any]) -> dict[str, Any]:
        from psycopg.types.json import Jsonb
        self.prune_cases()
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM cases")
            if int(cur.fetchone()["n"]) >= self.max_cases:
                raise ValueError("case_capacity")
        case_id = "case_" + uuid.uuid4().hex[:20]
        now = _utc_iso()
        status = data.get("status", "open")
        doc = {
            **data,
            "id": case_id,
            "created_at": now,
            "updated_at": now,
            "closed_at": now if status == "closed" else None,
            "status": status,
            "tags": list(data.get("tags", [])),
        }
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cases (id, created_at, status, document) VALUES (%s,%s,%s,%s)",
                (case_id, now, status, Jsonb(doc)),
            )
        self._case_log(case_id, "created", {
            "status": status,
            "severity": data.get("severity"),
            "classification_provenance": "analyst",
        })
        return self.get_case(case_id) or doc

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        doc = self._case_doc(case_id)
        if doc is None:
            return None
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, case_id, evidence_type, evidence_id, added_at "
                "FROM case_evidence WHERE case_id = %s ORDER BY added_at ASC, id ASC",
                (case_id,),
            )
            evidence_rows = cur.fetchall()
        result = dict(doc)
        result["tags"] = list(doc.get("tags") or [])
        result["evidence"] = [self._resolve_case_evidence(r) for r in evidence_rows]
        # Analyst notes are an SQLite-only Store extension (no add_case_note in
        # the StorageBackend contract); the core PG backend never writes them.
        result["notes"] = []
        result["history"] = self._case_history(case_id)
        result["classification_provenance"] = "analyst"
        result["evidence_provenance"] = "telemetry_reference"
        return result

    def update_case(self, case_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        from psycopg.types.json import Jsonb
        current = self._case_doc(case_id)
        if current is None:
            return None
        now = _utc_iso()
        changed: dict[str, Any] = {}
        updated = dict(current)
        for key in ("title", "summary", "status", "severity", "priority",
                    "owner", "conclusion", "hypotheses"):
            if key in data:
                updated[key] = data[key]
                changed[key] = data[key]
        if data.get("status") == "closed" and current.get("status") != "closed":
            updated["closed_at"] = now
        elif "status" in data and data["status"] != "closed" and current.get("status") == "closed":
            updated["closed_at"] = None
        if "tags" in data:
            updated["tags"] = list(data["tags"])
            changed["tags"] = updated["tags"]
        updated["id"] = case_id
        updated["updated_at"] = now
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE cases SET status = %s, document = %s WHERE id = %s",
                (updated.get("status"), Jsonb(updated), case_id),
            )
        if changed:
            changed["classification_provenance"] = "analyst"
            self._case_log(case_id, "updated", changed)
        return self.get_case(case_id)

    def delete_case(self, case_id: str) -> str:
        current = self._case_doc(case_id)
        if current is None:
            return "not_found"
        if current.get("status") != "closed":
            return "case_not_closed"
        # ON DELETE CASCADE removes the case's evidence/history rows too.
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM cases WHERE id = %s", (case_id,))
        return "deleted"

    def list_cases(self, *, limit: int = 100, q: str | None = None,
                   status: str | None = None, **_: Any) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 1000))
        clauses, params = [], []
        if status:
            clauses.append("status = %s")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(bounded)
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT document FROM cases{where} ORDER BY created_at DESC LIMIT %s",
                tuple(params),
            )
            items = [r["document"] for r in cur.fetchall()]
        if q:
            needle = q.lower()
            items = [c for c in items if needle in str(c.get("title", "")).lower()]
        return items

    def prune_cases(self, retention_days: int | None = None) -> int:
        days = self.case_retention_days if retention_days is None else max(0, int(retention_days))
        if days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        with self._conn.cursor() as cur:
            cur.execute("SELECT id, created_at FROM cases")
            stale = []
            for r in cur.fetchall():
                try:
                    ts = datetime.fromisoformat(str(r["created_at"]).replace("Z", "+00:00")).timestamp()
                except ValueError:
                    continue
                if ts < cutoff:
                    stale.append(r["id"])
            for cid in stale:
                cur.execute("DELETE FROM cases WHERE id = %s", (cid,))
        return len(stale)

    def set_ioc_resolver(self, resolver: Callable[[str], dict[str, Any] | None] | None) -> None:
        self._ioc_resolver = resolver

    # -- sensors / ops -----------------------------------------------------
    def reserve_sensor_nonce(self, sensor_id: str, nonce: str, *_: Any, **__: Any) -> bool:
        """Return True if the nonce is fresh (reserved now), False on replay."""
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensor_nonces(sensor_id, nonce, seen_at) VALUES (%s,%s,%s)
                   ON CONFLICT (sensor_id, nonce) DO NOTHING""",
                (str(sensor_id), str(nonce), _utc_iso()),
            )
            return cur.rowcount == 1

    def record_sensor_heartbeat(self, sensor_id: str, sensor_timestamp: str | None = None,
                                collector_received_at: str | None = None,
                                event_sequence: Any = None) -> dict[str, Any]:
        from psycopg.types.json import Jsonb
        bounded = str(sensor_id)[:96]
        if not bounded:
            raise ValueError("sensor_id is required")
        received = collector_received_at or _utc_iso()
        bounded_ts = str(sensor_timestamp)[:64] if sensor_timestamp else None
        doc = {"sensor_id": bounded, "sensor_timestamp": bounded_ts,
               "collector_received_at": received, "status": "healthy",
               "event_sequence": event_sequence}
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensor_heartbeats(sensor_id, last_seen_at, document) VALUES (%s,%s,%s)
                   ON CONFLICT (sensor_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at,
                       document = EXCLUDED.document""",
                (bounded, received, Jsonb(doc)),
            )
        return {"sensor_id": bounded, "sensor_timestamp": bounded_ts,
                "collector_received_at": received, "status": "healthy"}

    def _blank_sensor(self, sensor_id: str, configured: bool = False) -> dict[str, Any]:
        return {
            "sensor_id": sensor_id, "configured": configured,
            "last_received_at": None, "latest_event_timestamp": None,
            "total_events": 0, "recent_events": 0,
            "last_heartbeat_at": None, "sensor_heartbeat_timestamp": None,
            "heartbeat_state": "never",
        }

    def sensor_telemetry_observation(self, configured_sensor_ids=None, recent_hours: int = 24,
                                     heartbeat_stale_seconds: int = 180) -> dict[str, Any]:
        bounded_hours = max(1, min(int(recent_hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        observed: dict[str, dict[str, Any]] = {}
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT honeypot, MAX(collector_received_at) AS last_received_at, "
                "MAX(timestamp) AS latest_event_timestamp, COUNT(*) AS total_events, "
                "SUM(CASE WHEN collector_received_at >= %s THEN 1 ELSE 0 END) AS recent_events "
                "FROM events GROUP BY honeypot",
                (since,),
            )
            for row in cur.fetchall():
                sid = str(row["honeypot"])
                observed[sid] = {
                    **self._blank_sensor(sid),
                    "last_received_at": row["last_received_at"],
                    "latest_event_timestamp": row["latest_event_timestamp"],
                    "total_events": int(row["total_events"] or 0),
                    "recent_events": int(row["recent_events"] or 0),
                }
            cur.execute("SELECT sensor_id, last_seen_at, document FROM sensor_heartbeats")
            heartbeats = cur.fetchall()
        now = datetime.now(timezone.utc)
        stale_after = max(30, min(int(heartbeat_stale_seconds), 86400))
        for row in heartbeats:
            sid = str(row["sensor_id"])
            item = observed.setdefault(sid, self._blank_sensor(sid))
            received = str(row["last_seen_at"])
            try:
                received_dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                age = max(0, int((now - received_dt.astimezone(timezone.utc)).total_seconds()))
            except (TypeError, ValueError):
                age = stale_after + 1
            item["last_heartbeat_at"] = received
            item["sensor_heartbeat_timestamp"] = (row["document"] or {}).get("sensor_timestamp")
            item["heartbeat_age_seconds"] = age
            item["heartbeat_state"] = "healthy" if age <= stale_after else "stale"
        configured = {str(s)[:96] for s in (configured_sensor_ids or []) if str(s)}
        for sid in configured:
            observed.setdefault(sid, self._blank_sensor(sid, configured=True))["configured"] = True
        # The core PG backend does not track per-sensor event sequence numbers
        # (an SQLite-only feature), so every sensor is reported unsequenced.
        for item in observed.values():
            item["event_sequence"] = {"state": "unsequenced"}
        items = [observed[key] for key in sorted(observed, key=str.casefold)]
        return {
            "recent_hours": bounded_hours,
            "configured_sensors": len(configured),
            "configured_with_recent_telemetry": sum(
                1 for i in items if i["configured"] and i["recent_events"] > 0),
            "configured_with_healthy_heartbeat": sum(
                1 for i in items if i["configured"] and i["heartbeat_state"] == "healthy"),
            "heartbeat_stale_seconds": stale_after,
            "sensors_with_sequence_gaps": 0,
            "missing_sequenced_events": 0,
            "observed_sensor_ids": len(items),
            "items": items,
            "interpretation": (
                "Heartbeat state uses collector receipt time. Per-sensor event "
                "sequencing is not tracked by the PostgreSQL backend, so sensors "
                "are reported unsequenced."
            ),
        }

    def sensor_health(self, configured_sensor_ids=None, recent_hours: int = 24,
                      heartbeat_stale_seconds: int = 180) -> dict[str, Any]:
        observation = self.sensor_telemetry_observation(
            configured_sensor_ids=configured_sensor_ids,
            recent_hours=recent_hours,
            heartbeat_stale_seconds=heartbeat_stale_seconds,
        )
        hours = observation["recent_hours"]
        sensors: list[dict[str, Any]] = []
        silent: list[str] = []
        for item in observation["items"]:
            recent = int(item.get("recent_events") or 0)
            heartbeat = item.get("heartbeat_state")
            gaps = (item.get("event_sequence") or {}).get("state") == "gaps_detected"
            if item.get("configured") and recent == 0 and heartbeat in {"stale", "never"}:
                state = "silent"
            elif gaps or heartbeat == "stale":
                state = "degraded"
            else:
                state = "healthy"
            sensors.append({
                **item,
                "last_event_at": item.get("latest_event_timestamp"),
                "event_rate_per_hour": round(recent / hours, 3) if hours else 0.0,
                "sequence_gaps": gaps,
                "health": state,
            })
            if state == "silent":
                silent.append(str(item.get("sensor_id")))
        sensors.sort(key=lambda entry: str(entry.get("sensor_id")).casefold())
        return {
            "recent_hours": hours,
            "observation": observation,
            "sensors": sensors,
            "silent_sensors": silent,
            "silent_count": len(silent),
            "interpretation": (
                "A configured sensor is 'silent' when it has sent no telemetry in "
                "the window and its heartbeat is stale or absent."
            ),
        }

    def operational_health(self, min_free_bytes: int = 67_108_864) -> dict[str, Any]:
        try:
            with self._conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM events")
                event_count = int(cur.fetchone()["n"])
            database_ready = True
        except self._psycopg.Error:
            event_count = 0
            database_ready = False
        return {
            "ready": database_ready,
            "database_ready": database_ready,
            "state": "healthy" if database_ready else "critical",
            "backend": "postgresql",
            "storage": {"event_count": event_count},
        }

    def dashboard(self, *, hours: int = 24, **_: Any) -> dict[str, Any]:
        window = max(1, min(int(hours), 720))
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM events")
            total = int(cur.fetchone()["n"])
            cur.execute("SELECT severity, COUNT(*) AS n FROM events GROUP BY severity")
            by_severity = {str(r["severity"]): int(r["n"]) for r in cur.fetchall()}
        return {
            "generated_at": _utc_iso(),
            "window_hours": window,
            "backend": "postgresql",
            "totals": {"events": total},
            "by_severity": by_severity,
        }

    # Filter dimensions mapped to their location in the schema. honeypot /
    # event_type / severity are persisted columns; the rest are read from the
    # event jsonb document. All identifiers here are constants (no user input),
    # so interpolating them into SQL is safe.
    _FILTER_EXPR = {
        "country": "document->'enrichment'->'geoip'->>'country'",
        "asn": "document->'enrichment'->'geoip'->>'asn'",
        "destination_port": "document->'observed'->>'destination_port'",
        "protocol": "document->'observed'->>'protocol'",
        "service": "document->'observed'->>'service'",
        "honeypot": "honeypot",
        "severity": "severity",
        "event_type": "event_type",
    }

    def filter_options(self, hours: int = 720) -> dict[str, list[str]]:
        bounded_hours = max(1, min(int(hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        result: dict[str, list[str]] = {}
        for column, expr in self._FILTER_EXPR.items():
            with self._conn.cursor() as cur:
                cur.execute(
                    f"SELECT {expr} AS value, COUNT(*) AS n FROM events "
                    f"WHERE timestamp >= %s AND {expr} IS NOT NULL AND ({expr})::text <> '' "
                    f"GROUP BY {expr} ORDER BY n DESC, value ASC LIMIT 100",
                    (since,),
                )
                result[column] = [str(r["value"]) for r in cur.fetchall()]
        return result

    def evidence_loss_summary(self, hours: int = 24) -> dict[str, Any]:
        counters = self.counters()
        return {
            "window_hours": max(1, min(int(hours), 720)),
            "ingest_validation_rejections": counters.get("ingest_validation_rejections", 0),
            "load_shed_events": counters.get("load_shed_events", 0),
            "sensor_replay_rejections": counters.get("sensor_replay_rejections", 0),
        }

    # -- case evidence / report / timeline ---------------------------------
    def _resolve_case_evidence(self, row: dict[str, Any]) -> dict[str, Any]:
        """Resolve one evidence reference to a summary, mirroring Store.

        Availability means the referenced telemetry is still derivable/present
        in this backend, never a threat-intelligence verdict. The PG core
        backend stores no `sessions` or `alerts` domain, so those evidence
        kinds stay unavailable here (summary None) — honestly reported, not
        faked.
        """
        item = dict(row)
        evidence_type = item["evidence_type"]
        evidence_id = item["evidence_id"]
        item["available"] = False
        item["summary"] = None
        if evidence_type == "ioc":
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
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT id, timestamp, event_type, severity, source_ip, "
                    "session_id, honeypot, document FROM events WHERE id = %s",
                    (evidence_id,),
                )
                event = cur.fetchone()
            if event:
                observed = (event.get("document") or {}).get("observed") or {}
                item["available"] = True
                item["summary"] = {
                    "id": event["id"],
                    "timestamp": event["timestamp"],
                    "event_type": event["event_type"],
                    "severity": event["severity"],
                    "source_ip": event["source_ip"],
                    "session_id": event["session_id"],
                    "honeypot": event["honeypot"],
                    "service": observed.get("service"),
                    "protocol": observed.get("protocol"),
                    "destination_port": observed.get("destination_port"),
                }
        # evidence_type in ("session", "alert"): no such domain in the PG core
        # backend → left unavailable (summary None).
        return item

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

    def add_case_evidence(self, case_id: str, evidence_type: str, evidence_id: str) -> dict[str, Any] | None:
        # Validate derived-IOC existence up front via the injected resolver
        # (read-only), mirroring Store.
        ioc_available = None
        if evidence_type == "ioc":
            resolver = self._ioc_resolver
            if resolver is not None:
                try:
                    ioc_available = resolver(evidence_id)
                except Exception:
                    ioc_available = None
        if self._case_doc(case_id) is None:
            return None
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM case_evidence WHERE case_id=%s AND evidence_type=%s AND evidence_id=%s",
                (case_id, evidence_type, evidence_id),
            )
            if cur.fetchone():
                return self.get_case(case_id)
            cur.execute("SELECT COUNT(*) AS n FROM case_evidence WHERE case_id=%s", (case_id,))
            if int(cur.fetchone()["n"]) >= 1000:
                raise ValueError("case_evidence_limit")
        if evidence_type == "event":
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1 FROM events WHERE id = %s", (evidence_id,))
                available: Any = cur.fetchone()
        elif evidence_type == "ioc":
            available = ioc_available
        else:
            # session / alert are not domains of the PG core backend, so their
            # existence cannot be verified here; refuse rather than link an
            # unverifiable reference.
            available = None
        if not available:
            raise ValueError("evidence_not_found")
        now = _utc_iso()
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO case_evidence(case_id, evidence_type, evidence_id, added_at) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT (case_id, evidence_type, evidence_id) DO NOTHING",
                (case_id, evidence_type, evidence_id, now),
            )
            inserted = cur.rowcount
        if inserted:
            with self._conn.cursor() as cur:
                cur.execute(
                    "UPDATE cases SET document = jsonb_set(document, '{updated_at}', to_jsonb(%s::text)) "
                    "WHERE id = %s",
                    (now, case_id),
                )
            self._case_log(case_id, "evidence_added", {
                "type": evidence_type, "id": evidence_id, "provenance": "telemetry_reference",
            })
        return self.get_case(case_id)

    def case_report(self, case_id: str) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if not case:
            return None
        available = sum(1 for item in case["evidence"] if item["available"])
        unavailable = len(case["evidence"]) - available
        return {
            "report_type": "investigation_case",
            "generated_at": _utc_iso(),
            "case": {
                "id": case["id"],
                "title": case.get("title"),
                "status": case.get("status"),
                "severity": case.get("severity"),
                "priority": case.get("priority"),
                "owner": case.get("owner"),
                "summary": case.get("summary"),
                "conclusion": case.get("conclusion", ""),
                "hypotheses": case.get("hypotheses", ""),
                "tags": case["tags"],
                "created_at": case.get("created_at"),
                "updated_at": case.get("updated_at"),
                "closed_at": case.get("closed_at"),
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

    def case_timeline(self, case_id: str) -> dict[str, Any] | None:
        """Unified, chronologically ordered case timeline (see Store.case_timeline)."""
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


# Sanity: every method named in the contract exists on this class (all now
# implemented; the behavioural compatibility suite verifies their semantics).
assert all(hasattr(PostgresBackend, _m) for _m in REQUIRED_METHODS), (
    "PostgresBackend is missing a StorageBackend contract method"
)
