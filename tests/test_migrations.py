import sqlite3
import threading

import pytest

from aegis_nexus.alerts import AlertStore
from aegis_nexus.correlation_workspace import CorrelationWorkspace
from aegis_nexus.migrations import (
    LATEST_SCHEMA_VERSION,
    MIGRATIONS,
    Migration,
    SchemaVersionError,
    applied_migrations,
    apply_migrations,
    schema_version,
    validate_migrations,
)
from aegis_nexus.pcap import PcapEvidenceStore
from aegis_nexus.store import Store

EXPECTED_TABLES = {
    "sessions",
    "events",
    "cases",
    "case_tags",
    "case_evidence",
    "case_notes",
    "case_history",
    "alerts",
    "alert_evidence",
    "alert_tags",
    "alert_notes",
    "correlation_links",
    "pcap_evidence",
    "schema_migrations",
    "sensor_heartbeats",
}


def _tables(path) -> set[str]:
    with sqlite3.connect(path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _version(path) -> int:
    with sqlite3.connect(path) as conn:
        return schema_version(conn)


def test_fresh_database_is_created_at_latest_version_with_ledger(tmp_path):
    path = tmp_path / "fresh.db"
    Store(str(path))

    assert _version(path) == LATEST_SCHEMA_VERSION
    assert EXPECTED_TABLES <= _tables(path)
    with sqlite3.connect(path) as conn:
        ledger = applied_migrations(conn)
    assert [item["version"] for item in ledger] == [m.version for m in MIGRATIONS]
    assert ledger[0]["name"] == "baseline_unversioned_schema"


@pytest.mark.parametrize("component", [AlertStore, CorrelationWorkspace])
def test_every_component_brings_shared_database_to_latest_version(tmp_path, component):
    path = tmp_path / "component.db"
    component(str(path))

    assert _version(path) == LATEST_SCHEMA_VERSION
    assert EXPECTED_TABLES <= _tables(path)


def test_pcap_component_uses_shared_migrations(tmp_path):
    path = tmp_path / "pcap.db"
    PcapEvidenceStore(str(path), str(tmp_path / "pcap"))

    assert _version(path) == LATEST_SCHEMA_VERSION
    assert "pcap_evidence" in _tables(path)


def test_reopening_is_idempotent_and_does_not_rewrite_ledger(tmp_path):
    path = tmp_path / "reopen.db"
    Store(str(path))
    with sqlite3.connect(path) as conn:
        first = applied_migrations(conn)
        assert apply_migrations(conn) == []

    Store(str(path))
    AlertStore(str(path))
    with sqlite3.connect(path) as conn:
        assert applied_migrations(conn) == first


def test_unversioned_legacy_database_is_adopted_without_data_loss(tmp_path):
    path = tmp_path / "legacy.db"
    timestamp = "2026-08-01T10:00:00+00:00"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, honeypot TEXT NOT NULL,
                service TEXT NOT NULL, started_at TEXT NOT NULL, last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, honeypot TEXT NOT NULL,
                event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT,
                session_id TEXT NOT NULL, protocol TEXT, service TEXT, destination_port INTEGER,
                country TEXT, asn TEXT, latitude REAL, longitude REAL,
                observed TEXT NOT NULL, enrichment TEXT NOT NULL, derived TEXT NOT NULL,
                hypotheses TEXT NOT NULL, schema_version TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );
        """)
        conn.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",
            ("ses_legacy", "203.0.113.7", "ssh-old", "ssh", timestamp, timestamp, 1),
        )
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "54000000-0000-4000-8000-000000000001", timestamp, "ssh-old", "connection", "info",
                "203.0.113.7", "ses_legacy", "tcp", "ssh", 22, None, None, None, None,
                '{"source_ip":"203.0.113.7","service":"ssh","protocol":"tcp","destination_port":22}',
                "{}", "{}", "[]", "1.1",
            ),
        )
    assert _version(path) == 0

    store = Store(str(path), retention_days=0)

    assert _version(path) == LATEST_SCHEMA_VERSION
    event = store.get_event("54000000-0000-4000-8000-000000000001")
    assert event is not None
    assert event["received_at"] == timestamp
    with sqlite3.connect(path) as conn:
        session_columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    assert {"protocol", "destination_port"} <= session_columns


def test_database_from_newer_release_is_refused_and_left_untouched(tmp_path):
    path = tmp_path / "newer.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE future_only (id INTEGER)")
        conn.execute(f"PRAGMA user_version={LATEST_SCHEMA_VERSION + 1}")

    with pytest.raises(SchemaVersionError, match="newer than supported"):
        Store(str(path))

    assert _version(path) == LATEST_SCHEMA_VERSION + 1
    assert _tables(path) == {"future_only"}


def test_failed_migration_rolls_back_schema_data_and_version(tmp_path):
    path = tmp_path / "rollback.db"

    def create_table(conn):
        conn.execute("CREATE TABLE step_one (id INTEGER)")

    def half_applied(conn):
        conn.execute("CREATE TABLE step_two (id INTEGER)")
        conn.execute("INSERT INTO step_one VALUES (1)")
        raise RuntimeError("simulated migration failure")

    migrations = (Migration(1, "one", create_table), Migration(2, "two", half_applied))
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(RuntimeError, match="simulated"):
            apply_migrations(conn, migrations)
        assert schema_version(conn) == 1
        assert conn.execute("SELECT COUNT(*) FROM step_one").fetchone()[0] == 0
        assert [item["version"] for item in applied_migrations(conn)] == [1]
        assert conn.in_transaction is False
    finally:
        conn.close()
    assert "step_two" not in _tables(path)


def test_pending_migrations_apply_in_order_from_current_version(tmp_path):
    path = tmp_path / "ordered.db"
    calls = []

    def step(version):
        def apply(conn):
            calls.append(version)
            conn.execute(f"CREATE TABLE step_{version} (id INTEGER)")
        return apply

    conn = sqlite3.connect(path)
    try:
        assert apply_migrations(conn, (Migration(1, "one", step(1)),)) == [1]
        extended = (Migration(1, "one", step(1)), Migration(2, "two", step(2)), Migration(3, "three", step(3)))
        assert apply_migrations(conn, extended) == [2, 3]
        assert schema_version(conn) == 3
    finally:
        conn.close()
    assert calls == [1, 2, 3]


@pytest.mark.parametrize(
    "versions",
    [(), (2,), (1, 3), (1, 1)],
)
def test_migration_registry_must_be_contiguous(versions):
    migrations = tuple(Migration(v, f"m{v}", lambda conn: None) for v in versions)
    with pytest.raises(ValueError):
        validate_migrations(migrations)


def test_released_registry_is_valid():
    validate_migrations(MIGRATIONS)
    assert LATEST_SCHEMA_VERSION == MIGRATIONS[-1].version


def test_concurrent_startup_applies_each_migration_once(tmp_path):
    path = tmp_path / "concurrent.db"
    errors = []

    def start():
        try:
            Store(str(path))
        except Exception as exc:  # pragma: no cover - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert _version(path) == LATEST_SCHEMA_VERSION
    with sqlite3.connect(path) as conn:
        assert [item["version"] for item in applied_migrations(conn)] == [m.version for m in MIGRATIONS]


def test_operational_health_reports_schema_state(tmp_path):
    store = Store(str(tmp_path / "health.db"))
    health = store.operational_health(min_free_bytes=0)

    assert health["ready"] is True
    schema = health["database_schema"]
    assert schema["version"] == LATEST_SCHEMA_VERSION
    assert schema["latest_supported"] == LATEST_SCHEMA_VERSION
    assert schema["current"] is True
    assert [item["version"] for item in schema["migrations"]] == [m.version for m in MIGRATIONS]
