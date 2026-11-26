"""Behavioural compatibility suite for the StorageBackend contract (Cycle H).

`test_storage_backend.py` checks *structural* conformance (a backend exposes the
REQUIRED_METHODS with the right signatures). This suite checks *behavioural*
conformance: that a backend actually round-trips data and upholds the contract's
observable semantics (provenance-class preservation, observable counters, case
round-trip, health readiness).

It is written backend-agnostically: the `backend` fixture is parametrized over a
list of backend factories. Today only the reference SQLite `Store` is listed; a
future PostgreSQL backend (Cycle H / ADR 0002) is wired in by adding one entry
to `BACKENDS` — the whole suite then runs against it unchanged, which is exactly
the "backend compatibility tests" the roadmap calls for.
"""

from __future__ import annotations

import os

import pytest

from aegis_nexus.model import normalize_event
from aegis_nexus.storage_backend import REQUIRED_METHODS, StorageBackend
from aegis_nexus.store import COLLECTOR_COUNTERS, Store

# Backends the contract suite runs against. "postgres" runs only when a test
# PostgreSQL DSN is provided (and psycopg is installed); otherwise it skips, so
# the suite stays green everywhere while still proving cross-backend
# compatibility wherever a Postgres is available (locally or a CI service).
BACKENDS = ["sqlite", "postgres"]
_PG_DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")
_PG_TABLES = ("events", "cases", "counters", "sensor_heartbeats", "sensor_nonces")


def _make_backend(kind: str, tmp_path) -> StorageBackend:
    if kind == "sqlite":
        return Store(str(tmp_path / "aegis.db"))
    if kind == "postgres":
        if not _PG_DSN:
            pytest.skip("AEGIS_TEST_POSTGRES_DSN not set")
        try:
            import psycopg  # noqa: F401
        except ImportError:
            pytest.skip("psycopg not installed")
        from aegis_nexus.postgres_backend import PostgresBackend
        be = PostgresBackend(_PG_DSN)
        # Per-test isolation on the shared test database.
        with be._conn.cursor() as cur:
            cur.execute("TRUNCATE " + ", ".join(_PG_TABLES))
        return be
    raise AssertionError(f"unknown backend {kind!r}")


@pytest.fixture(params=BACKENDS)
def backend(request, tmp_path) -> StorageBackend:
    return _make_backend(request.param, tmp_path)


def _event(ip: str = "203.0.113.7") -> dict:
    return normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": "medium",
        "observed": {
            "source_ip": ip, "service": "ssh", "protocol": "tcp",
            "destination_port": 22, "command": "whoami",
        },
    })


def test_backend_satisfies_protocol(backend):
    assert isinstance(backend, StorageBackend)
    for method in REQUIRED_METHODS:
        assert callable(getattr(backend, method)), method


def test_ingest_then_get_event_roundtrips_and_preserves_provenance(backend):
    saved = backend.ingest(_event())
    got = backend.get_event(saved["id"])
    assert got is not None
    assert got["id"] == saved["id"]
    assert got["observed"]["command"] == "whoami"
    # The four provenance classes survive a store round-trip, never collapsed.
    for provenance_class in ("observed", "enrichment", "derived", "hypotheses"):
        assert provenance_class in got


def test_counter_increment_is_observable(backend):
    name = COLLECTOR_COUNTERS[0]
    before = backend.counters().get(name, 0)
    backend.increment_counter(name, 2)
    assert backend.counters().get(name, 0) == before + 2


def test_case_create_then_get_roundtrips(backend):
    case = backend.create_case({
        "title": "Compat case", "summary": "", "status": "open",
        "severity": "medium", "tags": ["compat"],
    })
    got = backend.get_case(case["id"])
    assert got is not None
    assert got["id"] == case["id"]


def test_operational_health_reports_readiness(backend):
    health = backend.operational_health()
    assert "ready" in health
    assert "database_ready" in health


def test_dashboard_returns_a_mapping(backend):
    backend.ingest(_event())
    dashboard = backend.dashboard(hours=24)
    assert isinstance(dashboard, dict)
