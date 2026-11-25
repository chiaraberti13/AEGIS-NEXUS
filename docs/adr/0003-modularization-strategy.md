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

**Frontend split — steps taken (2026-11-25):** `app.js` is now loaded as a native
ES module (`<script type="module">`, no build step). A leaf module `core.js`
(cycle-free — it imports nothing from app.js) now holds the shared foundation
that per-view modules need: the mutable `state`, the base helpers (`$`, `t`,
`pretty`, `apiHeaders`), the network layer (`getJSON`, `safeGet`) and the filter
helpers (`currentParams`, `feedParams`, `activeFilterCount`, `updateFilterCount`).
The one app→UI dependency of the network layer (showing the operator gate on a
401) is inverted via an injected hook (`setUnauthorizedHandler`), registered by
app.js at bootstrap — the same dependency-injection pattern used for the backend
blueprints.

Per-view modules are now being split out on this foundation, one view at a time.
First view extracted: the geospatial attack map (`map.js`) — it imports only from
`core.js`, and its one orchestration dependency (re-running `refresh()` when a
map point sets the country filter) is inverted via an injected hook
(`setMapRefresh`) that app.js registers at bootstrap. Each view extraction is
verified by the browser smoke test. The remaining view sections
(dashboard/alerts/iocs/cases/relations/audit/health) follow the same pattern. The ES-module conversion is guarded by the
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
