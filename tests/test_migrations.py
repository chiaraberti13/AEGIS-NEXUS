import sqlite3
import threading

import pytest

from aegis_nexus.alerts import AlertStore
from aegis_nexus.correlation_workspace import CorrelationWorkspace
from aegis_nexus.detection_suppression import DetectionSuppressionStore
from aegis_nexus.migrations import (
    LATEST_SCHEMA_VERSION,
    MIGRATIONS,
    Migration,
    MigrationBackupError,
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
    "detection_suppressions",
    "detection_suppression_audit",
    "sensor_replay_nonces",
    "sensor_sequence_streams",
    "sensor_sequence_ranges",
}

MIGRATION_SENTINEL_ID = "54000000-0000-4000-8000-000000000001"
MIGRATION_SENTINEL_TIMESTAMP = "2026-08-01T10:00:00+00:00"
RELEASED_MIGRATION_IDENTITIES = (
    (1, "baseline_unversioned_schema"),
    (2, "sensor_heartbeats"),
    (3, "detection_suppressions"),
    (4, "sensor_replay_nonces"),
    (5, "sensor_sequences"),
    (6, "event_hash_chain"),
)


def _tables(path) -> set[str]:
    with sqlite3.connect(path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _version(path) -> int:
    with sqlite3.connect(path) as conn:
        return schema_version(conn)


def _seed_released_database(path, version: int) -> None:
    """Create a data-bearing database at an exact released schema version."""
    with sqlite3.connect(path) as conn:
        if version == 0:
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
                (
                    "ses_migration_sentinel",
                    "203.0.113.7",
                    "ssh-old",
                    "ssh",
                    MIGRATION_SENTINEL_TIMESTAMP,
                    MIGRATION_SENTINEL_TIMESTAMP,
                    1,
                ),
            )
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    MIGRATION_SENTINEL_ID,
                    MIGRATION_SENTINEL_TIMESTAMP,
                    "ssh-old",
                    "connection",
                    "info",
                    "203.0.113.7",
                    "ses_migration_sentinel",
                    "tcp",
                    "ssh",
                    22,
                    None,
                    None,
                    None,
                    None,
                    '{"source_ip":"203.0.113.7","service":"ssh","protocol":"tcp","destination_port":22}',
                    "{}",
                    "{}",
                    "[]",
                    "1.1",
                ),
            )
            return

        apply_migrations(conn, MIGRATIONS[:version], backup_dir=path.parent / "seed-backups")
        conn.execute(
            """
            INSERT INTO sessions(
                id,source_ip,honeypot,service,protocol,destination_port,
                started_at,last_seen,event_count
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                "ses_migration_sentinel",
                "203.0.113.7",
                "ssh-release",
                "ssh",
                "tcp",
                22,
                MIGRATION_SENTINEL_TIMESTAMP,
                MIGRATION_SENTINEL_TIMESTAMP,
                1,
            ),
        )
        conn.execute(
            """
            INSERT INTO events(
                id,timestamp,received_at,honeypot,event_type,severity,source_ip,session_id,
                protocol,service,destination_port,observed,enrichment,derived,hypotheses,
                collector,schema_version,collector_received_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                MIGRATION_SENTINEL_ID,
                MIGRATION_SENTINEL_TIMESTAMP,
                MIGRATION_SENTINEL_TIMESTAMP,
                "ssh-release",
                "connection",
                "info",
                "203.0.113.7",
                "ses_migration_sentinel",
                "tcp",
                "ssh",
                22,
                '{"source_ip":"203.0.113.7","service":"ssh","protocol":"tcp","destination_port":22}',
                "{}",
                "{}",
                "[]",
                "{}",
                "1.1",
                MIGRATION_SENTINEL_TIMESTAMP,
            ),
        )


def test_fresh_database_is_created_at_latest_version_with_ledger(tmp_path):
    path = tmp_path / "fresh.db"
    Store(str(path))

    assert _version(path) == LATEST_SCHEMA_VERSION
    assert EXPECTED_TABLES <= _tables(path)
    with sqlite3.connect(path) as conn:
        ledger = applied_migrations(conn)
    assert [item["version"] for item in ledger] == [m.version for m in MIGRATIONS]
    assert ledger[0]["name"] == "baseline_unversioned_schema"


@pytest.mark.parametrize("component", [AlertStore, CorrelationWorkspace, DetectionSuppressionStore])
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
    _seed_released_database(path, 0)
    assert _version(path) == 0

    store = Store(str(path), retention_days=0)

    assert _version(path) == LATEST_SCHEMA_VERSION
    event = store.get_event(MIGRATION_SENTINEL_ID)
    assert event is not None
    assert event["received_at"] == MIGRATION_SENTINEL_TIMESTAMP
    with sqlite3.connect(path) as conn:
        session_columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    assert {"protocol", "destination_port"} <= session_columns


@pytest.mark.parametrize(
    "released_version",
    range(LATEST_SCHEMA_VERSION),
    ids=lambda version: f"v{version}_to_v{LATEST_SCHEMA_VERSION}",
)
def test_upgrade_from_every_previously_released_schema_version(tmp_path, released_version):
    path = tmp_path / f"released-v{released_version}.db"
    backup_dir = tmp_path / f"backups-v{released_version}"
    _seed_released_database(path, released_version)

    assert _version(path) == released_version
    with sqlite3.connect(path) as conn:
        applied = apply_migrations(conn, backup_dir=backup_dir)
        event = conn.execute(
            "SELECT timestamp,received_at,collector_received_at FROM events WHERE id=?",
            (MIGRATION_SENTINEL_ID,),
        ).fetchone()
        ledger = applied_migrations(conn)

    assert applied == [
        migration.version for migration in MIGRATIONS if migration.version > released_version
    ]
    assert _version(path) == LATEST_SCHEMA_VERSION
    assert EXPECTED_TABLES <= _tables(path)
    assert event == (
        MIGRATION_SENTINEL_TIMESTAMP,
        MIGRATION_SENTINEL_TIMESTAMP,
        MIGRATION_SENTINEL_TIMESTAMP,
    )
    assert [item["version"] for item in ledger] == [migration.version for migration in MIGRATIONS]

    backups = list(
        backup_dir.glob(
            f"aegis-pre-migration-v{released_version}-to-v{LATEST_SCHEMA_VERSION}-*.db"
        )
    )
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert schema_version(backup) == released_version
        assert backup.execute(
            "SELECT timestamp FROM events WHERE id=?", (MIGRATION_SENTINEL_ID,)
        ).fetchone()[0] == MIGRATION_SENTINEL_TIMESTAMP


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


def test_existing_database_is_backed_up_before_pending_migration(tmp_path):
    path = tmp_path / "upgrade.db"
    backup_dir = tmp_path / "backups"

    def step_one(conn):
        conn.execute("CREATE TABLE evidence (value TEXT NOT NULL)")

    def step_two(conn):
        conn.execute("ALTER TABLE evidence ADD COLUMN classification TEXT")

    first = (Migration(1, "one", step_one),)
    extended = (*first, Migration(2, "two", step_two))
    with sqlite3.connect(path) as conn:
        assert apply_migrations(conn, first, backup_dir=backup_dir) == [1]
        conn.execute("INSERT INTO evidence(value) VALUES('observed-before-upgrade')")
        conn.commit()
        assert apply_migrations(conn, extended, backup_dir=backup_dir) == [2]

    backups = list(backup_dir.glob("aegis-pre-migration-v1-to-v2-*.db"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert schema_version(backup) == 1
        assert backup.execute("SELECT value FROM evidence").fetchone()[0] == "observed-before-upgrade"
        assert {row[1] for row in backup.execute("PRAGMA table_info(evidence)")} == {"value"}
    assert _version(path) == 2


def test_backup_failure_aborts_before_migration_changes(tmp_path, monkeypatch):
    path = tmp_path / "fail-closed.db"

    def step_one(conn):
        conn.execute("CREATE TABLE evidence (value TEXT NOT NULL)")

    def step_two(conn):
        conn.execute("ALTER TABLE evidence ADD COLUMN classification TEXT")

    first = (Migration(1, "one", step_one),)
    extended = (*first, Migration(2, "two", step_two))
    with sqlite3.connect(path) as conn:
        apply_migrations(conn, first, backup_dir=tmp_path / "backups")

    def fail_backup(*args, **kwargs):
        raise OSError("simulated read-only backup target")

    monkeypatch.setattr("aegis_nexus.migrations.backup_database", fail_backup)
    with sqlite3.connect(path) as conn:
        with pytest.raises(MigrationBackupError, match="pre-migration backup failed"):
            apply_migrations(conn, extended, backup_dir=tmp_path / "unwritable")
        assert schema_version(conn) == 1
        assert {row[1] for row in conn.execute("PRAGMA table_info(evidence)")} == {"value"}
        assert conn.in_transaction is False


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
    identities = tuple((migration.version, migration.name) for migration in MIGRATIONS)
    assert identities == RELEASED_MIGRATION_IDENTITIES


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
