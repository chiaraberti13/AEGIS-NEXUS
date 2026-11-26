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
_PG_TABLES = ("events", "cases", "counters", "sensor_heartbeats",
              "sensor_nonces", "schema_migrations")


def _make_backend(kind: str, tmp_path) -> StorageBackend:
    if kind == "sqlite":
        return Store(str(tmp_path / "aegis.db"))
    if kind == "postgres":
        if not _PG_DSN:
            pytest.skip("AEGIS_TEST_POSTGRES_DSN not set")
        try:
            import psycopg
        except ImportError:
            pytest.skip("psycopg not installed")
        # Clean slate BEFORE instantiating the backend: a prior test may have
        # left the shared DB in any state (incl. a future ledger version that
        # the backend would refuse at init).
        with psycopg.connect(_PG_DSN, autocommit=True) as conn, conn.cursor() as cur:
            for table in _PG_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
        from aegis_nexus.postgres_backend import PostgresBackend
        return PostgresBackend(_PG_DSN)
    raise AssertionError(f"unknown backend {kind!r}")


@pytest.fixture(params=BACKENDS)
def backend(request, tmp_path) -> StorageBackend:
    return _make_backend(request.param, tmp_path)


def _event(ip: str = "203.0.113.7", ts: str | None = None) -> dict:
    payload = {
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": "medium",
        "observed": {
            "source_ip": ip, "service": "ssh", "protocol": "tcp",
            "destination_port": 22, "command": "whoami",
        },
    }
    if ts is not None:
        payload["timestamp"] = ts
    return normalize_event(payload)


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


def test_page_events_paginates_every_ingested_event(backend):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ingested = {
        backend.ingest(_event(ts=(base + timedelta(minutes=i)).isoformat()))["id"]
        for i in range(3)
    }
    first = backend.page_events(limit=2)
    assert len(first["items"]) == 2
    assert first["has_more"] is True
    assert first["next_cursor"]
    second = backend.page_events(limit=2, cursor=first["next_cursor"])
    seen = {e["id"] for e in first["items"]} | {e["id"] for e in second["items"]}
    assert ingested <= seen


def test_filter_options_lists_persisted_dimensions(backend):
    backend.ingest(_event())
    opts = backend.filter_options()
    assert set(opts) == {
        "country", "asn", "destination_port", "protocol",
        "service", "honeypot", "severity", "event_type",
    }
    assert "ssh-1" in opts["honeypot"]
    assert "command" in opts["event_type"]
