"""PostgreSQL migration-strategy tests (Cycle H / ADR 0002).

Mirror of the SQLite migration guarantees (test_migrations.py) for the optional
PostgreSQL backend: a transactional `schema_migrations` ledger replaces SQLite's
PRAGMA user_version. These run only when a test PostgreSQL DSN is provided
(AEGIS_TEST_POSTGRES_DSN) and psycopg is installed; otherwise they skip.
"""

from __future__ import annotations

import os

import pytest

_PG_DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")
_PG_TABLES = ("case_evidence", "case_history", "events", "cases", "counters",
              "sensor_heartbeats", "sensor_nonces", "schema_migrations")


def _require_pg():
    if not _PG_DSN:
        pytest.skip("AEGIS_TEST_POSTGRES_DSN not set")
    try:
        import psycopg  # noqa: F401
    except ImportError:
        pytest.skip("psycopg not installed")
    return psycopg


@pytest.fixture
def clean_pg():
    psycopg = _require_pg()
    with psycopg.connect(_PG_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            for table in _PG_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    return _PG_DSN


def test_migrations_apply_to_latest_on_a_fresh_database(clean_pg):
    from aegis_nexus.postgres_backend import PostgresBackend, POSTGRES_SCHEMA_VERSION
    backend = PostgresBackend(clean_pg)
    assert backend.schema_version() == POSTGRES_SCHEMA_VERSION
    assert backend.schema_version_applied == list(range(1, POSTGRES_SCHEMA_VERSION + 1))


def test_migrations_are_idempotent(clean_pg):
    from aegis_nexus.postgres_backend import PostgresBackend, apply_pg_migrations
    backend = PostgresBackend(clean_pg)
    # Re-running against an already-migrated database applies nothing.
    assert apply_pg_migrations(backend._conn) == []


def test_ledger_records_every_applied_migration(clean_pg):
    from aegis_nexus.postgres_backend import PostgresBackend, POSTGRES_SCHEMA_VERSION
    backend = PostgresBackend(clean_pg)
    with backend._conn.cursor() as cur:
        cur.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version")
        rows = cur.fetchall()
    assert [r["version"] for r in rows] == list(range(1, POSTGRES_SCHEMA_VERSION + 1))
    for row in rows:
        assert row["name"] and row["applied_at"]


def test_migration_refuses_a_future_schema_version(clean_pg):
    from aegis_nexus.postgres_backend import PostgresBackend, apply_pg_migrations
    from aegis_nexus.migrations import SchemaVersionError
    backend = PostgresBackend(clean_pg)
    with backend._conn.cursor() as cur:
        cur.execute(
            "INSERT INTO schema_migrations(version, name, applied_at) VALUES (999, 'future', 'x')"
        )
    with pytest.raises(SchemaVersionError):
        apply_pg_migrations(backend._conn)
