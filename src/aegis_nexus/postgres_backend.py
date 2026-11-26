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
from datetime import datetime, timezone
from typing import Any, Callable

from .storage_backend import REQUIRED_METHODS


class PostgresBackendUnsupported(NotImplementedError):
    """Raised for StorageBackend methods not implemented by the core PG backend."""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA = """
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


class PostgresBackend:
    """PostgreSQL-backed core persistence implementing the StorageBackend contract."""

    def __init__(self, dsn: str, *, max_cases: int = 10_000, case_retention_days: int = 0) -> None:
        import psycopg  # lazy: only required when this backend is actually used
        from psycopg.rows import dict_row

        self._psycopg = psycopg
        self.max_cases = max(1, min(int(max_cases), 1_000_000))
        self.case_retention_days = max(0, min(int(case_retention_days), 3650))
        self._ioc_resolver: Callable[[str], dict[str, Any] | None] | None = None
        self._conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
        self._init_schema()

    # -- lifecycle ---------------------------------------------------------
    def _init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)
            from .store import COLLECTOR_COUNTERS
            for name in COLLECTOR_COUNTERS:
                cur.execute(
                    "INSERT INTO counters(name, value) VALUES (%s, 0) ON CONFLICT (name) DO NOTHING",
                    (name,),
                )

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

    def page_events(self, *, limit: int = 100, **_: Any) -> dict[str, Any]:
        bounded = max(1, min(int(limit), 500))
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT document FROM events ORDER BY collector_received_at DESC, id DESC LIMIT %s",
                (bounded,),
            )
            items = [r["document"] for r in cur.fetchall()]
        # Cursor paging parity with Store is out of scope for the core backend.
        return {"items": items, "next_cursor": None, "has_more": False}

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

    def detection_context(self, *a: Any, **k: Any) -> Any:
        self._unsupported("detection_context")

    def behavioral_context(self, *a: Any, **k: Any) -> Any:
        self._unsupported("behavioral_context")

    def filter_options(self, *a: Any, **k: Any) -> Any:
        self._unsupported("filter_options")

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
