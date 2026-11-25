# ADR 0003 — Modularization strategy (incremental extraction)

- Status: **Accepted**
- Date: 2026-11-24
- Context: ROADMAP Cycle I — "Split monolithic storage responsibilities into
  modules" (and the per-domain event/session/alert/case/analytics/relationship
  splits), "Split API routes by domain", "Introduce explicit service layer
  where useful", "Review frontend module boundaries", "Split `static/app.js`
  into ES modules by view without adding a mandatory build step".

## Context

`store.py` (~2000 lines) and `app.py`/`app.js` (~2000–2500 lines each) are the
project's large modules. The Cycle I items propose breaking them into
per-domain modules, a service layer and per-view ES modules.

A single big-bang refactor of these files would be a large, high-churn change on
security-critical code (migrations, hash chain, PRAGMAs, auth/trust boundary,
safe-DOM rendering). It carries real regression risk, is hard to review, and
delivers little behavioural value on its own.

The ROADMAP already prescribes the safer approach: *"when a cycle touches
store.py/app.py/app.js, extract the touched domain into its own module instead
of growing the monolith."*

## Decision

**Adopt incremental extraction; defer the big-bang split.**

- New domains and features are added as their own focused modules, not by
  growing the monoliths. This session already followed that: `metrics.py`,
  `logging_config.py`, `forwarding.py`, `redaction.py`, `evidence_bundle.py`,
  `pdf.py`, `soc_summary.py`, `detection_coverage.py` and `storage_backend.py`
  were added as separate modules. The `StorageBackend` interface (ADR-adjacent)
  began the storage-abstraction boundary.
- When a future change touches a storage domain (events, sessions, alerts,
  cases, analytics, relationships) it extracts that domain behind a cohesive
  interface at that time, keeping `Store` as the composed reference backend and
  public API behaviour unchanged (guarded by `tests/test_api_contract.py`).
- A dedicated service layer is introduced only where a concrete need appears
  (it is "where useful", not mandatory).

## Update (2026-11-25) — splits carried out

The incremental extraction above has since been executed, all behaviour-preserving
and guarded by the contract/store tests:

- **Storage split (done):** six domains were extracted from `store.py`
  (~2400→~940 lines): `store_relations.py` (pure function) and the
  `store_cases.py`, `store_analytics.py`, `store_events.py`, `store_sessions.py`
  mixins that `Store` composes, with shared constants in the dependency-free
  `store_common.py`. The alert domain already lived in `alerts.py`. `Store`
  remains the composed reference backend.
- **API-route split (done):** `app.py` (~1833→~977 lines) was split into twelve
  domain blueprints via a **blueprint-factory pattern** — a module-level
  `make_<domain>_blueprint(...)` captures its dependencies explicitly (never
  importing `app`, so no cycle) and returns a Flask `Blueprint` with the same
  absolute URLs. The app-level `before_request` trust boundary and
  `after_request` security headers still run for blueprint routes, so
  operator/sensor authentication is unchanged. The authenticated ingest/identity
  core (events, Suricata, quarantine, sensor heartbeat, `/`, `/health`, operator
  status) stays in the factory by design.

**Frontend boundaries review:** `static/app.js` is a single IIFE with a central
`state` object and clear internal sections by view (api/i18n helpers, feed,
dashboard, alerts, iocs, cases, relations, audit, health, map). The
boundaries are already view-oriented. Splitting into native ES modules
(`<script type="module">` with relative imports, no build step) is feasible but
would require threading the shared `state`/helpers across modules and re-testing
every view; it is deferred until it can be done without regressing the
safe-DOM/i18n invariants. The module boundaries and the intended split are
documented in `docs/ARCHITECTURE.md`.

**Frontend split — step taken (2026-11-25):** `app.js` is now loaded as a native
ES module (`<script type="module">`, no build step), and the shared mutable
`state` plus the base helpers (`$`, `t`, `pretty`, `apiHeaders`) are extracted
into a leaf module `core.js` that app.js imports as live bindings. This is
cycle-free (core imports nothing from app.js). Splitting the per-view sections
into their own modules is **still deferred**: those sections call back into
app.js helpers (`refresh`, `updateFilterCount`, `safeGet`, …), so extracting them
today would create import cycles rather than cleaner boundaries. A future step
would first lift those cross-cutting helpers into `core.js` (or a sibling leaf
module), then move each view. The ES-module conversion is guarded by the
browser XSS smoke test (`tests/browser/xss_smoke.cjs`) and the safe-DOM/i18n
checks now scan every `static/*.js` module.

## Consequences

- The remaining Cycle I split/service-layer items stay unchecked and are tracked
  by this ADR; "Review frontend module boundaries" is satisfied (documented
  here and in `docs/ARCHITECTURE.md`).
- Already delivered in Cycle I: the mypy gate, API contract tests, the internal
  architecture doc, and the Playwright XSS browser smoke test.
- Each future extraction must keep public API behaviour backward compatible
  (contract tests) and the evidence-first/safe-DOM invariants intact, and should
  land as a small, reviewable change — never a big-bang rewrite.

## Notes

See ADR 0001 (Sigma export) and ADR 0002 (PostgreSQL backend) for the ADR
convention. ADRs live under `docs/adr/NNNN-title.md`.
