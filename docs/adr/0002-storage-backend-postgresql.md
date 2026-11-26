# ADR 0002 — StorageBackend abstraction and optional PostgreSQL backend

- Status: **Accepted** (defer implementation; revisit on a concrete multi-node need)
- Date: 2026-11-24
- Context: ROADMAP Cycle H — "Define StorageBackend interface", "Refactor SQLite
  backend behind StorageBackend", "Add optional PostgreSQL backend", "Extend the
  Cycle P migration strategy to PostgreSQL", "Add backend compatibility tests",
  "Document SQLite vs PostgreSQL deployment profiles".

## Context

AEGIS-NEXUS deliberately uses raw SQLite (WAL, no ORM) as a single-node,
file-based store. The Cycle H items propose abstracting storage behind a
`StorageBackend` interface and adding an optional PostgreSQL backend for larger,
multi-node deployments.

Several properties of the current design are tightly coupled to SQLite and would
need careful re-expression on PostgreSQL without changing investigation
semantics:

- the forward-only migration framework keyed on `PRAGMA user_version`, each
  migration in its own `BEGIN IMMEDIATE` with a pre-migration file backup and a
  refusal to open a database written by a newer release;
- the event hash chain and `PRAGMA`-based integrity (`quick_check`,
  `integrity_check`, `secure_delete`, WAL) used by backup and restore
  verification;
- WAL-specific operations (checkpoint/truncate) in maintenance and the
  file-copy backup/restore path;
- bounded, parameterized raw SQL throughout `store.py`.

## Decision

**Defer the StorageBackend abstraction and the PostgreSQL backend.** They are
not implemented in this cycle. Reasons:

- No current deployment requires multi-node/concurrent-writer storage; the
  honeypot collector is a single-node service and SQLite-WAL meets its bounds.
  Introducing an abstraction now would be speculative generality.
- A PostgreSQL backend cannot be built and verified in this project's test and
  CI environment without provisioning a PostgreSQL service and a parallel
  migration/integrity story, which is out of scope here. Shipping an
  unverifiable second backend would violate the project rule against declaring
  something correct without verification.
- The investigation semantics and evidence-first guarantees must be identical
  across backends; proving that needs a backend-parity test suite that only has
  value once a second backend actually exists.

## Consequences

- The six Cycle H storage-backend items stay unchecked and are tracked by this
  ADR rather than being marked done.
- Observability work that does **not** depend on a storage abstraction was
  completed instead (platform state, Prometheus metrics, JSON logging, sensor
  health, restore verification, evidence-loss metrics).
- When a concrete multi-node need appears, a superseding ADR should define the
  `StorageBackend` interface first (events, sessions, alerts, cases, analytics,
  relationships, migrations, integrity), keep the SQLite backend as the
  reference implementation, add a PostgreSQL backend behind it, port the
  migration strategy (a transactional schema-version ledger in place of
  `PRAGMA user_version`), and add a backend-parity test suite asserting
  identical investigation results. Only then should these items be checked.

## Update (2026-11-26) — core PostgreSQL backend implemented

The `StorageBackend` interface now has a second, opt-in implementation:
`src/aegis_nexus/postgres_backend.py` (`PostgresBackend`, psycopg 3, installed
via the `postgres` extra). SQLite `Store` stays the default reference backend.

Scope — **core persistence, verified against a real PostgreSQL 16**:

- event ingest + fetch (full event JSON in a `jsonb` column, the four
  provenance classes preserved), bounded recent-event paging;
- collector counters, operator cases (CRUD + list + retention prune), sensor
  heartbeats, sensor nonce anti-replay;
- operational health and a SQL-computed dashboard rollup.

The behavioural compatibility suite (`tests/test_backend_compatibility.py`) is
parametrized over SQLite **and** PostgreSQL and passes on both (the Postgres
leg runs wherever `AEGIS_TEST_POSTGRES_DSN` is set — locally and via the CI
`postgres:16` service). This is the backend-parity assertion this ADR called
for, at the core-contract level.

The migration strategy is now ported too: `apply_pg_migrations` maintains a
transactional `schema_migrations` ledger (replacing SQLite's
`PRAGMA user_version`), applying forward-only steps each under a session
advisory lock so concurrent workers never double-apply, and **refusing** a
database whose version exceeds the latest known migration (`SchemaVersionError`)
rather than migrating it down. Guarded by `tests/test_postgres_migrations.py`
(apply-to-latest, idempotence, ledger rows, future-version refusal) against real
PostgreSQL. So all three storage items — "optional PostgreSQL backend",
"backend compatibility tests" and "extend the migration strategy to
PostgreSQL" — are done at the core-persistence level.

Analytics surface — incrementally extended on top of the foundation, each
method verified on SQLite **and** PostgreSQL by the parametrized compatibility
suite. Implemented on PostgreSQL so far: `page_events` (filters on persisted
columns, time window, opaque cursor paging via the shared `pagination` module),
`filter_options` (persisted columns + jsonb-derived dimensions),
`detection_context` (same-source-IP and credential-fingerprint evidence in a
timestamp-anchored window; fingerprints only, never raw secrets),
`behavioral_context` (historical baseline ending at the anchor, excluding it),
and the sensor rollups `sensor_telemetry_observation` + `sensor_health` (per
honeypot event aggregation + heartbeat freshness; per-sensor event sequencing is
an SQLite-only feature, so PG reports sensors unsequenced).

Still deferred (methods raise `PostgresBackendUnsupported`, not silently wrong
data): the case evidence/report/timeline methods (`add_case_evidence`,
`case_report`, `case_timeline`). These need the richer case schema —
case_evidence / case_history / case_notes, plus sessions and alerts — ported to
PostgreSQL first. That schema-plus-logic port is the remaining Store-API-surface
extension, independent of the storage/migration foundation, tracked here outside
the closed Cycle H cluster.

## Notes

This supersedes nothing; it records why the Cycle H storage-backend cluster is
intentionally deferred. See ADR 0001 for the first ADR and the ADR convention
(`docs/adr/NNNN-title.md`).
