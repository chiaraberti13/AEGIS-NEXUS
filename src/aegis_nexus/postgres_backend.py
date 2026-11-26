"""Optional PostgreSQL storage backend (Cycle H / ADR 0002).

A concrete :class:`~aegis_nexus.storage_backend.StorageBackend` implementation
backed by PostgreSQL (via psycopg 3). SQLite ``Store`` stays the default
reference backend; this backend is opt-in (`pip install '.[postgres]'`).

Scope — **core persistence**, verified by the behavioural compatibility suite
(`tests/test_backend_compatibility.py`) against a real PostgreSQL:

- event ingest + fetch (full event JSON in a ``jsonb`` column, provenance
  classes preserved), bounded recent-event paging;
- collector counters, operator cases (CRUD + list), sensor heartbeats, sensor
  nonce anti-replay, case retention pruning;
- operational health and a basic dashboard rollup computed in SQL.

The richer analytical surface that ``Store`` grows over SQLite — detection and
behavioural context windows, filter options, sensor telemetry/health rollups,
case evidence resolution, case report and timeline — is **not** reimplemented
here; those methods raise :class:`PostgresBackendUnsupported` with a clear
message rather than returning silently wrong data. Extending them is tracked by
ADR 0002. This keeps the claim honest: Postgres is a verified core-persistence
backend, not yet a drop-in replacement for the full Store API surface.

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


# Forward-only PostgreSQL migrations, mirroring the SQLite strategy
# (migrations.py): a transactional `schema_migrations` ledger replaces SQLite's
# PRAGMA user_version. Append a new (version, name, sql) tuple to evolve the
# schema; never edit or reorder a released migration. Each step runs in its own
# transaction under a session advisory lock, so concurrent workers re-read the
# version under the lock and never apply a step twice; a database written by a
# newer release is refused, not migrated down.
_PG_MIGRATIONS: tuple[tuple[int, str, str], ...] = (
    (1, "baseline", _BASELINE_SQL),
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
    def create_case(self, data: dict[str, Any]) -> dict[str, Any]:
        from psycopg.types.json import Jsonb
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM cases")
            if int(cur.fetchone()["n"]) >= self.max_cases:
                raise ValueError("case_capacity")
        case_id = str(uuid.uuid4())
        now = _utc_iso()
        doc = {
            **data,
            "id": case_id,
            "created_at": now,
            "updated_at": now,
            "status": data.get("status", "open"),
        }
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cases (id, created_at, status, document) VALUES (%s,%s,%s,%s)",
                (case_id, now, doc["status"], Jsonb(doc)),
            )
        return doc

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT document FROM cases WHERE id = %s", (case_id,))
            row = cur.fetchone()
        return row["document"] if row else None

    def update_case(self, case_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        from psycopg.types.json import Jsonb
        current = self.get_case(case_id)
        if current is None:
            return None
        updated = {**current, **data, "id": case_id, "updated_at": _utc_iso()}
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE cases SET status = %s, document = %s WHERE id = %s",
                (updated.get("status"), Jsonb(updated), case_id),
            )
        return updated

    def delete_case(self, case_id: str) -> str:
        current = self.get_case(case_id)
        if current is None:
            return "not_found"
        if current.get("status") != "closed":
            return "case_not_closed"
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM cases WHERE id = %s", (case_id,))
        return case_id

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

    def record_sensor_heartbeat(self, sensor_id: str, *, sensor_timestamp: str | None = None,
                                event_sequence: Any = None, **_: Any) -> dict[str, Any]:
        from psycopg.types.json import Jsonb
        now = _utc_iso()
        doc = {"sensor_id": sensor_id, "last_seen_at": now,
               "sensor_timestamp": sensor_timestamp, "event_sequence": event_sequence}
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensor_heartbeats(sensor_id, last_seen_at, document) VALUES (%s,%s,%s)
                   ON CONFLICT (sensor_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at,
                       document = EXCLUDED.document""",
                (str(sensor_id), now, Jsonb(doc)),
            )
        return doc

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

    # -- not implemented in the core backend (ADR 0002) --------------------
    def _unsupported(self, name: str) -> Any:
        raise PostgresBackendUnsupported(
            f"{name}() is not implemented by the core PostgreSQL backend; "
            "it belongs to Store's rich analytical surface (ADR 0002)."
        )

    def sensor_telemetry_observation(self, *a: Any, **k: Any) -> Any:
        self._unsupported("sensor_telemetry_observation")

    def sensor_health(self, *a: Any, **k: Any) -> Any:
        self._unsupported("sensor_health")

    def add_case_evidence(self, *a: Any, **k: Any) -> Any:
        self._unsupported("add_case_evidence")

    def case_report(self, *a: Any, **k: Any) -> Any:
        self._unsupported("case_report")

    def case_timeline(self, *a: Any, **k: Any) -> Any:
        self._unsupported("case_timeline")


# Sanity: every method named in the contract exists on this class (presence,
# even where the body raises PostgresBackendUnsupported).
assert all(hasattr(PostgresBackend, _m) for _m in REQUIRED_METHODS), (
    "PostgresBackend is missing a StorageBackend contract method"
)
