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
_PG_TABLES = ("case_evidence", "case_history", "events", "cases", "counters",
              "sensor_heartbeats", "sensor_nonces", "schema_migrations")


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


def test_detection_context_gathers_same_source_ip_window(backend):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 3, 1, tzinfo=timezone.utc)
    ip = "198.51.100.7"
    prior = backend.ingest(_event(ip=ip, ts=base.isoformat()))
    anchor = backend.ingest(_event(ip=ip, ts=(base + timedelta(hours=1)).isoformat()))
    other = backend.ingest(_event(ip="203.0.113.9", ts=(base + timedelta(minutes=30)).isoformat()))
    ctx = backend.detection_context(anchor, lookback_hours=24)
    ids = {e["id"] for e in ctx}
    assert anchor["id"] in ids       # the anchor event itself is always included
    assert prior["id"] in ids        # same source IP, within the window
    assert other["id"] not in ids    # different source IP is excluded


def test_behavioral_context_excludes_anchor_and_reports_window(backend):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 4, 1, tzinfo=timezone.utc)
    older = backend.ingest(_event(ts=base.isoformat()))
    anchor = backend.ingest(_event(ts=(base + timedelta(days=1)).isoformat()))
    ctx = backend.behavioral_context(anchor, days=30)
    ids = {e["id"] for e in ctx["events"]}
    assert anchor["id"] not in ids   # anchor excluded so it can't train its own baseline
    assert older["id"] in ids        # earlier event is in the baseline window
    assert ctx["analysis"]["anchor_event_id"] == anchor["id"]
    assert ctx["analysis"]["scope"] == "historical_events_excluding_anchor"


def test_sensor_telemetry_observation_reports_configured_and_heartbeat(backend):
    backend.ingest(_event())  # honeypot "ssh-1"
    backend.record_sensor_heartbeat("ssh-1")
    obs = backend.sensor_telemetry_observation(configured_sensor_ids=["ssh-1"], recent_hours=24)
    assert obs["configured_sensors"] == 1
    item = next(i for i in obs["items"] if i["sensor_id"] == "ssh-1")
    assert item["configured"] is True
    assert item["recent_events"] >= 1
    assert item["heartbeat_state"] == "healthy"
    assert item["event_sequence"]["state"] == "unsequenced"


def test_sensor_health_flags_silent_configured_sensor(backend):
    # A configured sensor with no telemetry and no heartbeat is "silent".
    health = backend.sensor_health(configured_sensor_ids=["ghost-sensor"], recent_hours=24)
    ghost = next(s for s in health["sensors"] if s["sensor_id"] == "ghost-sensor")
    assert ghost["health"] == "silent"
    assert "ghost-sensor" in health["silent_sensors"]
    # An active sensor (events + fresh heartbeat) is healthy, not silent.
    backend.ingest(_event())
    backend.record_sensor_heartbeat("ssh-1")
    health2 = backend.sensor_health(configured_sensor_ids=["ssh-1"], recent_hours=24)
    active = next(s for s in health2["sensors"] if s["sensor_id"] == "ssh-1")
    assert active["health"] == "healthy"


def test_add_case_evidence_links_event_and_rejects_unknown(backend):
    event = backend.ingest(_event())
    case = backend.create_case({
        "title": "Evidence case", "summary": "", "status": "open",
        "severity": "medium", "tags": [],
    })
    # A real event can be linked; the evidence reference is resolved & available.
    updated = backend.add_case_evidence(case["id"], "event", event["id"])
    assert updated is not None
    linked = [e for e in updated["evidence"] if e["evidence_id"] == event["id"]]
    assert len(linked) == 1
    assert linked[0]["available"] is True
    assert linked[0]["summary"]["id"] == event["id"]
    # Idempotent: linking the same evidence twice does not duplicate it.
    again = backend.add_case_evidence(case["id"], "event", event["id"])
    assert sum(1 for e in again["evidence"] if e["evidence_id"] == event["id"]) == 1
    # A reference to telemetry that does not exist is refused, never faked.
    with pytest.raises(ValueError):
        backend.add_case_evidence(case["id"], "event", "event_does_not_exist")
    # An unknown case id yields None (not an exception).
    assert backend.add_case_evidence("case_missing", "event", event["id"]) is None


def test_case_report_counts_available_and_unavailable_evidence(backend):
    event = backend.ingest(_event())
    case = backend.create_case({
        "title": "Report case", "summary": "sum", "status": "open",
        "severity": "high", "tags": ["report"],
    })
    backend.add_case_evidence(case["id"], "event", event["id"])
    report = backend.case_report(case["id"])
    assert report is not None
    assert report["report_type"] == "investigation_case"
    assert report["case"]["id"] == case["id"]
    assert report["case"]["classification_provenance"] == "analyst"
    assert report["statistics"]["evidence_references"] == 1
    assert report["statistics"]["available_references"] == 1
    assert report["statistics"]["unavailable_references"] == 0
    assert report["limitations"]            # provenance caveats are always present
    assert backend.case_report("case_missing") is None


def test_case_timeline_merges_analyst_actions_and_observed_time(backend):
    from datetime import datetime, timezone
    observed_ts = datetime(2026, 5, 1, tzinfo=timezone.utc).isoformat()
    event = backend.ingest(_event(ts=observed_ts))
    case = backend.create_case({
        "title": "Timeline case", "summary": "", "status": "open",
        "severity": "low", "tags": [],
    })
    backend.add_case_evidence(case["id"], "event", event["id"])
    timeline = backend.case_timeline(case["id"])
    assert timeline is not None
    assert timeline["schema_version"] == "1.0"
    kinds = {e["kind"] for e in timeline["entries"]}
    # case lifecycle (created) + evidence link (analyst) + observed sensor time.
    assert "case.created" in kinds
    assert "evidence.linked" in kinds
    assert "evidence.observed" in kinds
    observed = next(e for e in timeline["entries"] if e["kind"] == "evidence.observed")
    assert observed["provenance"] == "observed"
    assert observed["timestamp"] == observed_ts
    # Entries are chronologically ordered and never exceed the cap.
    stamps = [str(e["timestamp"]) for e in timeline["entries"]]
    assert stamps == sorted(stamps)
    assert timeline["entry_count"] == len(timeline["entries"]) <= 1000
    assert backend.case_timeline("case_missing") is None


def test_case_evidence_ioc_resolved_via_injected_resolver(backend):
    # IOC evidence is a derived artifact resolved by the injected resolver;
    # this proves add/report work identically on both backends for the `ioc`
    # kind, without either backend needing an IOC table.
    backend.set_ioc_resolver(lambda eid: {
        "id": eid, "type": "ipv4", "value": "203.0.113.7",
        "classification": "scanner", "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-02T00:00:00+00:00", "occurrences": 3,
    } if eid == "ioc_known" else None)
    case = backend.create_case({
        "title": "IOC case", "summary": "", "status": "open",
        "severity": "medium", "tags": [],
    })
    updated = backend.add_case_evidence(case["id"], "ioc", "ioc_known")
    ioc = next(e for e in updated["evidence"] if e["evidence_type"] == "ioc")
    assert ioc["available"] is True
    assert ioc["summary"]["evidence_provenance"] == "derived_artifact"
    # An IOC the resolver cannot derive is refused.
    with pytest.raises(ValueError):
        backend.add_case_evidence(case["id"], "ioc", "ioc_unknown")


def test_event_hash_chain_is_an_explicit_sqlite_only_capability(backend):
    """The tamper-evident event hash chain is SQLite-only (ADR 0002).

    Both backends must answer ``verify_event_chain`` so a caller that iterates
    backends never ``AttributeError``s or silently skips the integrity check;
    the PostgreSQL answer must declare the feature unsupported rather than imply
    a verified-intact chain.
    """
    report = backend.verify_event_chain()
    if isinstance(backend, Store):
        assert report["ok"] is True
        assert "record_hash_mismatch" not in {p["type"] for p in report["problems"]}
    else:  # PostgresBackend
        assert report["supported"] is False
        assert report["ok"] is False
        assert "ADR 0002" in report["reason"]
