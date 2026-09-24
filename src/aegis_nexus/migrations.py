"""Versioned, forward-only schema migrations for the shared AEGIS SQLite database.

Every component that owns tables in the collector database (events/sessions/cases,
alerts, correlation links, PCAP evidence) shares one file, so the schema has one
version number: SQLite's ``PRAGMA user_version``. Each migration runs in its own
``BEGIN IMMEDIATE`` transaction together with the version bump and a ledger row
in ``schema_migrations``; a failing migration rolls back completely and leaves the
previous version in place. A database written by a newer release is refused rather
than silently modified, because there are no down-migrations.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class SchemaVersionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def enable_wal(conn: sqlite3.Connection, timeout_seconds: float = 5.0) -> None:
    """Switch to WAL, retrying while another process converts a brand-new file.

    Changing the journal mode can return SQLITE_BUSY without invoking the busy
    handler, which made concurrent first starts (several Gunicorn workers) fail
    with "database is locked". Once a file is in WAL mode the pragma is a no-op.
    """
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if ("locked" not in message and "busy" not in message) or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _execute_statements(conn: sqlite3.Connection, script: str) -> None:
    # executescript() would COMMIT the surrounding migration transaction, so the
    # trusted, project-owned DDL below is executed one statement at a time.
    for statement in script.split(";"):
        if statement.strip():
            conn.execute(statement)


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


_CORE_TABLES = """
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
    CREATE INDEX IF NOT EXISTS idx_case_history_case ON case_history(case_id, timestamp)
"""

_ALERT_TABLES = """
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
    CREATE INDEX IF NOT EXISTS idx_alerts_rule_source ON alerts(rule_id,source_ip,status,last_seen DESC)
"""

_CORRELATION_TABLES = """
    CREATE TABLE IF NOT EXISTS correlation_links (
        id TEXT PRIMARY KEY,
        source_session_id TEXT NOT NULL,
        related_session_id TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        method TEXT NOT NULL,
        score REAL NOT NULL,
        strength TEXT NOT NULL,
        evidence_basis TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE(source_session_id, related_session_id, method)
    );
    CREATE INDEX IF NOT EXISTS idx_correlation_links_source
    ON correlation_links(source_session_id, score DESC, last_seen DESC)
"""

_PCAP_TABLES = """
    CREATE TABLE IF NOT EXISTS pcap_evidence (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        format TEXT NOT NULL,
        storage_name TEXT NOT NULL UNIQUE,
        capture_provider TEXT,
        FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_pcap_evidence_session
    ON pcap_evidence(session_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_pcap_evidence_created
    ON pcap_evidence(created_at ASC)
"""


def _baseline(conn: sqlite3.Connection) -> None:
    """Adopt unversioned databases: create missing tables and apply legacy column upgrades.

    Every statement is idempotent, so this is safe on an empty file and on any
    database written before schema versioning existed.
    """
    _execute_statements(conn, _CORE_TABLES)

    event_columns = _column_names(conn, "events")
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

    session_columns = _column_names(conn, "sessions")
    if "protocol" not in session_columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT NOT NULL DEFAULT 'unknown'")
    if "destination_port" not in session_columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN destination_port INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_lookup_v2 "
        "ON sessions(source_ip, honeypot, service, protocol, destination_port, last_seen)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_page "
        "ON sessions(last_seen DESC, id DESC)"
    )

    _execute_statements(conn, _ALERT_TABLES)
    _execute_statements(conn, _CORRELATION_TABLES)
    _execute_statements(conn, _PCAP_TABLES)


def _sensor_heartbeats(conn: sqlite3.Connection) -> None:
    _execute_statements(
        conn,
        """
        CREATE TABLE IF NOT EXISTS sensor_heartbeats (
            sensor_id TEXT PRIMARY KEY,
            sensor_timestamp TEXT,
            collector_received_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'healthy'
        );
        CREATE INDEX IF NOT EXISTS idx_sensor_heartbeats_received
        ON sensor_heartbeats(collector_received_at DESC)
        """,
    )


# Append new migrations at the end with the next integer version. Never edit or
# reorder a migration that has been released: deployed databases already recorded it.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "baseline_unversioned_schema", _baseline),
    Migration(2, "sensor_heartbeats", _sensor_heartbeats),
)

LATEST_SCHEMA_VERSION = MIGRATIONS[-1].version

_LEDGER = """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
"""


def validate_migrations(migrations: tuple[Migration, ...]) -> None:
    if not migrations:
        raise ValueError("at least one migration is required")
    for expected, migration in enumerate(migrations, start=1):
        if migration.version != expected:
            raise ValueError(
                f"migration versions must be contiguous from 1; expected {expected}, got {migration.version}"
            )


def schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def apply_migrations(
    conn: sqlite3.Connection,
    migrations: tuple[Migration, ...] = MIGRATIONS,
) -> list[int]:
    """Bring the database to the latest schema version and return the versions applied."""
    validate_migrations(migrations)
    latest = migrations[-1].version
    current = schema_version(conn)
    if current > latest:
        raise SchemaVersionError(
            f"database schema version {current} is newer than supported version {latest}; "
            "upgrade AEGIS-NEXUS or restore a compatible backup"
        )
    if current == latest:
        return []

    applied: list[int] = []
    previous_isolation = conn.isolation_level
    conn.isolation_level = None  # explicit transaction control below
    try:
        for migration in migrations:
            # BEGIN IMMEDIATE takes the write lock first, so concurrent workers
            # re-read the version under the lock and never apply a step twice.
            conn.execute("BEGIN IMMEDIATE")
            try:
                if schema_version(conn) >= migration.version:
                    conn.execute("COMMIT")
                    continue
                migration.apply(conn)
                conn.execute(_LEDGER)
                conn.execute(
                    "INSERT OR REPLACE INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
                    (migration.version, migration.name, datetime.now(timezone.utc).isoformat()),
                )
                conn.execute(f"PRAGMA user_version={int(migration.version)}")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            applied.append(migration.version)
    finally:
        conn.isolation_level = previous_isolation
    return applied


def applied_migrations(conn: sqlite3.Connection) -> list[dict[str, object]]:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if not exists:
        return []
    return [
        {"version": int(row[0]), "name": str(row[1]), "applied_at": str(row[2])}
        for row in conn.execute("SELECT version,name,applied_at FROM schema_migrations ORDER BY version")
    ]
