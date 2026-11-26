# 🛡️ AEGIS-NEXUS Roadmap

> Development roadmap for evolving AEGIS-NEXUS into a modern **Honeypot + SOC Analysis + Threat Research + Cybersecurity Learning Lab**.

This document is the project's implementation checklist. Items are checked only after the feature is implemented, tested and integrated without weakening evidence provenance, sensor isolation, privacy or hostile-input handling.

**Legend:** `[ ]` planned · `[x]` completed · _(evaluate)_ = research spike: the outcome may be an ADR that rejects the feature

### Definition of Done (per item)

An item may be checked only when **all** of the following hold:

1. Implementation merged with CI green on the merge commit.
2. Tests cover the happy path **and** hostile/oversized/malformed input for anything that touches captured data.
3. Evidence provenance is explicit (Observed / Enrichment / Derived / Hypotheses) and evidence loss is recorded, never silent.
4. New data fields are reviewed for privacy impact (source IPs, usernames and credentials are personal data) and covered by retention.
5. New attack surface or new data flow is reflected in `docs/THREAT_MODEL.md`.
6. User-facing text exists in both IT and EN.
7. Relevant documentation under `docs/` is updated in the same change.

### Non-goals

These are deliberate design boundaries, not missing features:

- No hack-back, counter-scanning or any active action against observed sources.
- No execution of attacker-supplied commands, binaries or scripts in any sensor (emulation only).
- No automatic outbound retrieval of attacker-referenced URLs/payloads from sensors.
- No threat-actor or human attribution derived from infrastructure, TI matches or correlation scores.
- No opaque ML/AI scoring presented as evidence; deterministic, explainable analytics come first.

---

## ✅ Foundation already completed

- [x] SSH decoy with emulated interaction and command telemetry
- [x] Web decoy with login, request and payload telemetry
- [x] FTP and Telnet legacy decoys
- [x] Authenticated and signed sensor telemetry
- [x] Per-sensor secrets and management-network source binding
- [x] Separate sensor management networks
- [x] Host-side decoy egress guard
- [x] Hardened containers and resource limits
- [x] Hostile-input normalization and bounded storage
- [x] Evidence Integrity metadata for collector transformations
- [x] Sensor-side truncation/rejection provenance
- [x] Credential redaction and evidence-safe fingerprinting
- [x] SQLite persistence, retention and online backup
- [x] Explicit and heuristic session correlation with provenance
- [x] SOC dashboard and Live Feed
- [x] Attack Map
- [x] Analytical charts and global filters/search
- [x] IP and session investigation views
- [x] Deterministic IOC/artifact extraction
- [x] Offline GeoIP/ASN enrichment
- [x] Local exact-match Threat Context
- [x] Native Suricata EVE JSON ingestion
- [x] Evidence-backed MITRE ATT&CK/CVE handling
- [x] Relationship graph
- [x] Case management
- [x] JSON/CSV/Markdown reporting
- [x] Bilingual IT/EN interface
- [x] Security, privacy, provenance, isolation and operations documentation
- [x] CI regression/security tests and Docker build validation

---

## Cycle A — SOC Detection & Alerting

**Goal:** turn raw telemetry into evidence-backed SOC alerts without inventing attribution or unsupported conclusions.

- [x] Define versioned detection-rule schema
- [x] Implement Detection Engine
- [x] Keep detection `severity` and `confidence` separate
- [x] Store rule ID, rule version and evidence references for every alert
- [x] Implement alert deduplication and aggregation
- [x] Implement alert lifecycle: New → Acknowledged → Investigating → Closed
- [x] Add analyst notes and tags to alerts
- [x] Add Alerts API
- [x] Add SOC Alert Queue
- [x] Add Alert Detail investigation view
- [x] Link alerts to events, sessions, IOC and cases
- [x] Implement `multiple_auth_failures`
- [x] Implement `credential_reuse`
- [x] Implement `credential_bruteforce`
- [x] Implement `web_scanning`
- [x] Implement `path_traversal_sequence`
- [x] Implement `recon_burst`
- [x] Implement `command_staging_detected`
- [x] Implement `download_attempt`
- [x] Implement `rapid_port_sequence`
- [x] Implement `suricata_high_severity`
- [x] Add detection-rule tests and false-positive regression fixtures
- [x] Document detection semantics and limitations in IT/EN

**Done when:** every alert can be traced back to concrete stored evidence and the UI explains why the detection fired.

---

## Cycle B — Correlation & Investigation 2.0

**Goal:** make relationships between telemetry directly useful during investigations.

- [x] Extend correlation across IP, session, username and credential fingerprint
- [x] Correlate commands, payload hashes, URLs, domains and other IOC
- [x] Correlate ports, services, ASN and Suricata alerts
- [x] Introduce explainable correlation scoring
- [x] Store correlation method, score and evidence basis
- [x] Prevent correlation score from being presented as attribution
- [x] Add IOC Workspace
- [x] Add IOC first-seen / last-seen / occurrence statistics
- [x] Link IOC to sessions, source IPs, sensors, alerts and cases
- [x] Add IOC search/filter/export
- [x] Upgrade Relationship Graph with node-type filters
- [x] Add on-demand graph expansion
- [x] Add graph depth controls
- [x] Add evidence-only graph mode
- [x] Add provenance cues to graph nodes/edges
- [x] Add graph side inspector
- [x] Add evidence-path highlighting
- [x] Add Find Path between two investigation entities
- [x] Add graph/correlation regression tests

**Done when:** an analyst can move from an alert or IOC to all supporting evidence and understand exactly why each relationship exists.

---

## Cycle P — Platform Readiness & Integrity Hardening

**Goal:** close integrity, trust and maintainability gaps that later cycles depend on (new columns, new sensors, per-analyst workflow) before the data model grows further.

**Why first:** new schema fields, new sensors and Cycle G analyst identity all build on this cycle. Schema changes now go through versioned migrations (`src/aegis_nexus/migrations.py`); signed sensor requests now carry single-use nonces and per-stream sequence numbers that expose telemetry gaps, and named per-analyst operator identities are now accepted alongside the single-key lab mode, and an append-only operator audit log (`src/aegis_nexus/operator_audit.py`) records alert-lifecycle changes, case changes, exports and PCAP/artifact access, and is now surfaced to operators in a read-only dashboard Audit view and, case-scoped, inside JSON/Markdown case reports. Operator accountability is complete; the remaining Cycle P work is the supply-chain & CI security hardening below.

### Schema & data lifecycle
- [x] Add versioned, forward-only SQLite schema migrations (`PRAGMA user_version`)
- [x] Take an automatic online backup before applying migrations
- [x] Add migration tests from every previously released schema version
- [x] Add a versioned synthetic attack-replay corpus (SSH/Web/FTP/Telnet/Suricata fixtures) for regression tests in later cycles

### Sensor trust & evidence integrity
- [x] Add sensor replay protection (per-sensor nonce cache bounded to the signature skew window)
- [x] Add per-sensor monotonic sequence numbers to detect telemetry gaps as evidence loss
- [x] Add a tamper-evident hash chain over stored events (`prev_hash` / `record_hash`)
- [x] Add an offline integrity-verification command for the event hash chain and backups
- [x] Document zero-downtime rotation of sensor and operator secrets (overlapping keys)

### Operator accountability
- [x] Support multiple named operator identities (per-analyst keys) while keeping the single-key lab mode
- [x] Add an append-only operator audit log (alert lifecycle, case changes, exports, PCAP/artifact access)
- [x] Surface the audit log in the UI and in case reports

### Supply chain & CI security

> **Local tooling in place (CI wiring deferred).** The repository currently
> ships no GitHub Actions workflow, so these items — which require "CI green" per
> the Definition of Done — stay unchecked. The reproducible **local** equivalents
> now exist and are documented in `docs/SUPPLY_CHAIN.md`: a dependency-free
> CycloneDX SBOM generator (`make sbom`), a reviewed bandit baseline
> (`.bandit-baseline.json`, `make sast`), a `pip-audit` target (`make audit`), a
> high-signal `ruff` lint gate (`make lint`, enforced by `tests/test_lint.py`)
> and a `mypy` type gate (`make typecheck`, `tests/test_typecheck.py`). Wiring
> them into a CI workflow is a maintainer decision pending the reinstated
> pipeline.

- [x] Add lint/format checks to CI (e.g. `ruff`) _(`.github/workflows/ci.yml` job `lint`: `ruff check src tests scripts`)_
- [x] Add dependency vulnerability scanning to CI (e.g. `pip-audit`) _(job `dependency-audit`: `pip-audit` over the hash-locked `requirements.lock`; found + triaged PYSEC-2026-2858, see SUPPLY_CHAIN.md)_
- [x] Add Python SAST to CI (e.g. `bandit`) with a reviewed baseline _(job `sast`: `bandit -r src --baseline .bandit-baseline.json`)_
- [x] Add secret scanning to CI (e.g. `gitleaks`) _(job `secret-scan`: `gitleaks/gitleaks-action` over full history)_
- [x] Add container image vulnerability scanning (e.g. Trivy) for the built image _(job `container`: Trivy scan of the built image, CRITICAL/HIGH, ignore-unfixed)_
- [x] Generate an SBOM (CycloneDX) for each build _(job `sbom`: CycloneDX via `scripts/generate_sbom.py --reproducible`, uploaded as an artifact)_
- [x] Pin GitHub Actions by commit SHA and enable automated dependency updates _(all CI actions pinned to immutable commit SHAs with a `# vX.Y.Z` comment — `actions/checkout@11d5960…` (v4.4.0), `actions/setup-python@a26af69…` (v5.6.0), `actions/upload-artifact@ea165f8…` (v4.6.2), `gitleaks/gitleaks-action@ff98106…` (v2.3.9), `aquasecurity/trivy-action@915b19b…` (v0.28.0); SHAs resolved from each upstream repo's tags via the git proxy. `.github/dependabot.yml` keeps the github-actions + pip ecosystems current and bumps both the SHA and the version comment. This closes the supply-chain gap where a moved tag could swap action code — ADR + `docs/SUPPLY_CHAIN.md`.)_
- [x] Add hash-locked dependency constraints for reproducible container builds _(`requirements.lock` via `pip-compile --generate-hashes`; the Dockerfile installs it with `--require-hashes`, then the project with `--no-deps`)_

**Done when:** schema changes are migrated safely, replayed or missing sensor telemetry is detectable, stored evidence is tamper-evident, analyst actions are attributable to a named operator, and CI blocks known-vulnerable or secret-leaking changes.

---

## Cycle C — Network Evidence & Visibility

**Goal:** add network-level context while keeping collection bounded and privacy-aware.

**Note:** the original Cycle C scope is complete. The additional items below extend it and depend on Cycle P (migrations, replay corpus).

- [x] Define network-evidence schema and provenance
- [x] Capture connection duration
- [x] Capture bytes in/out where sensors can observe them
- [x] Capture packet/connection counters where available
- [x] Capture relevant TCP metadata without claiming unsupported OS attribution
- [x] Improve HTTP header and User-Agent evidence
- [x] Capture SSH client version string _(observed.network.ssh.client_version, bounded per RFC 4253; tooling hint, never identity)_
- [x] Capture SSH KEX/cipher offer lists _(the client's `SSH_MSG_KEXINIT` offer lists — `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`, `compression_algorithms` (c2s) — captured on `connection.identified` under `observed.network.ssh`, bounded (≤128×64) and collector-re-validated; tooling hint, never identity. Captured via a snapshot of paramiko's `remote_kex_init` in a `_parse_kex_init` override, with a fail-safe: if a future paramiko changes that internal, capture is simply skipped, never crashes — ADR 0005)_
- [x] Add HASSH-style SSH client fingerprints (fingerprint = tooling hint, never identity) _(HASSH = Salesforce `md5(kex;enc_c2s;mac_c2s;comp_c2s)`, BSD-3-Clause (not JA4+), computed natively from the captured KEXINIT and stored as `observed.network.ssh.hassh` (+ `hassh_algorithms`); omitted when offer lists are truncated so a stored digest always matches real tooling. Guarded by `tests/test_sensors.py` + collector-side validation tests in `tests/test_network_evidence.py` — ADR 0005)_
- [ ] Add HTTP client fingerprints (e.g. JA4H) after licence review _(licence review **done** — ADR 0005: JA4H is under the FoxIO License 1.1, a non-commercial-only licence that is **GPLv3-incompatible**, and the methods are patent-pending, so a native implementation is **declined**; JA4H values remain available by ingesting them from an external producer (Suricata/Zeek) as observed evidence)_
- [x] Add optional TLS metadata/fingerprints where technically available
- [ ] Add sensor-native JA4 TLS fingerprints (Suricata JA3/JA3S/JA4 passthrough already exists) _(licence review **done** — ADR 0005: JA4/TLS is **BSD-3-Clause**, GPLv3-compatible, so a native implementation is **permitted**; kept low-priority on-demand since Suricata passthrough already provides JA4 today, and native capture needs a decoy that reads the TLS ClientHello)_
- [x] Add DNS indicator evidence where available
- [x] Design optional passive fingerprint provider interface
- [x] Evaluate optional Zeek log ingestion (`conn`, `http`, `ssh`, `dns`) with the same provenance model as Suricata _(evaluate)_ — see `docs/adr/0004-zeek-log-ingestion.md` (feasible; implement on demand)
- [x] Add optional bounded PCAP capture mode
- [x] Run PCAP capture in a dedicated capture container (`CAP_NET_RAW` only, never inside decoys) _(opt-in overlay `docker-compose.pcap.yml` + `docker/pcap/`: one tcpdump sidecar per decoy sharing the decoy netns via `network_mode: service:<decoy>`; the sidecar holds `CAP_NET_RAW`, the decoy keeps `cap_drop: ALL`; read-only + `no-new-privileges`, drops to `nobody`. Isolation invariants CI-checked by `scripts/verify_compose_isolation.py`. Live capture is deployment-verified, not unit-testable — `docs/PCAP_CAPTURE.md`, ADR 0005)_
- [x] Restrict capture with BPF filters to decoy ports/interfaces _(each sidecar captures non-promiscuously (`tcpdump -p`) with a BPF filter scoped to its decoy's listening port(s); sharing the decoy netns means only that decoy's own traffic is visible — ADR 0005)_
- [x] Use ring-buffer capture so disk usage has a hard upper bound _(tcpdump `-C`/`-W` ring of `AEGIS_PCAP_RING_FILES`×`AEGIS_PCAP_RING_MB` MB per decoy, oldest overwritten; snaplen bounded; values validated/clamped in `docker/pcap/capture.sh` — ADR 0005)_
- [x] Add PCAP size limits
- [x] Add PCAP retention limits
- [x] Hash retained PCAP evidence with SHA-256
- [x] Associate PCAP evidence with session IDs
- [x] Serve PCAP only as authenticated, audited attachment downloads (never parsed or rendered in the browser)
- [x] Add Network Evidence investigation panel
- [x] Add network-evidence security/privacy documentation
- [x] Add bounded-capture and hostile-input tests

> **Remaining extension items decided** (see `docs/adr/0005-network-fingerprints-and-pcap-capture.md`). SSH client version/KEX + HASSH is deferred until it no longer needs private paramiko state; HTTP (JA4H) / TLS (JA4) fingerprints are blocked pending licence review (product/legal); dedicated-container PCAP capture (BPF, ring-buffer) is an opt-in deployment pattern (privileged capture sidecar), while the collector-side bounds already hold. No sensor gains new capability or egress, and nothing fingerprint/capture is shipped unverified.

**Done when:** network evidence enriches investigations without creating unlimited packet retention or unsupported attribution.

---

## Cycle D — Sensor Platform & Honeypot Expansion

**Goal:** make sensors modular and add new emulated attack surfaces safely.

- [x] Define common Sensor interface
- [x] Implement sensor registry
- [x] Move existing SSH sensor to plugin architecture
- [x] Move existing Web sensor to plugin architecture
- [x] Move existing FTP/Telnet sensors to plugin architecture
- [x] Add declarative sensor configuration
- [x] Add sensor capability metadata
- [x] Add sensor heartbeat so silent-but-healthy sensors are distinguishable from dead sensors
- [x] Add configurable decoy personas (banners, hostnames, fake filesystem) per deployment
- [x] Remove static default fingerprints and test decoys against common honeypot-detection checks
- [x] Add SMTP decoy
- [x] Add Redis decoy
- [x] Add MySQL decoy
- [x] Add SMB decoy
- [x] Evaluate PostgreSQL decoy
- [x] Evaluate RDP handshake decoy
- [x] Evaluate VNC decoy
- [x] Evaluate SNMP decoy
- [x] Add generic TCP banner decoy
- [x] Evaluate read-only Modbus/TCP ICS decoy _(evaluate)_
- [x] Add honeytokens/canary credentials planted in decoy content
- [x] Raise high-fidelity alerts when a planted honeytoken is reused on any sensor
- [x] Capture attacker uploads (FTP `STOR`, web uploads, SSH `scp`/`sftp` where emulated) into an inert quarantine store
- [x] Hash quarantined artifacts (SHA-256), enforce size/count limits and never serve them inline
- [x] Verify IPv6 listening, normalization and egress-guard coverage for every sensor
- [x] Ensure new decoys never execute attacker-supplied commands/payloads
- [x] Add isolation and hostile-input tests for every sensor
- [x] Document how to build third-party/custom sensors

**Done when:** a new protocol decoy can be added through the sensor interface without modifying the collector core.

---

## Cycle E — Threat Intelligence & CTI

**Goal:** turn enrichment into a provider-based CTI layer while preserving source provenance.

- [x] Define Threat Intelligence provider interface
- [x] Migrate Local JSON Threat Context to provider interface
- [x] Store provider/source/retrieval timestamp for every enrichment
- [x] Store confidence only when supplied by the source
- [x] Add indicator validity windows where available
- [x] Add feed/provider health information
- [x] Add STIX 2.x export
- [x] Add STIX 2.x import
- [x] Evaluate TAXII client support
- [x] Add configurable custom-feed adapter
- [x] Evaluate MISP export/import _(evaluate)_
- [x] Add TLP markings and sharing policy to CTI exports
- [x] Strip sensor-internal data (management IPs, sensor secrets, operator notes) from shareable exports
- [x] Add indicator aging/decay without deleting historical evidence
- [x] Add benign-scanner context lists as enrichment (never as silent suppression)
- [x] Keep observed telemetry separate from Threat Intelligence
- [x] Prevent TI matches from automatically creating attribution
- [x] Prevent TI matches from inventing MITRE/CVE relationships
- [x] Add CTI provenance tests
- [x] Document provider trust and enrichment limitations

**Done when:** every intelligence assertion is attributable to a named source and timestamp and remains separate from observed evidence.

---

## Cycle F — Behavioral Analytics

**Goal:** identify noteworthy changes and bursts using explainable deterministic analytics before considering ML/AI.

- [x] Implement baseline framework
- [x] Add minimum-sample thresholds so cold-start baselines do not produce findings
- [x] Add 24-hour baseline
- [x] Add 7-day baseline
- [x] Add 30-day baseline
- [x] Detect new source IP
- [x] Detect new country
- [x] Detect new ASN
- [x] Detect new username
- [x] Detect new payload hash
- [x] Detect new URL/domain
- [x] Detect rare command
- [x] Detect command-frequency spike
- [x] Detect authentication-attempt burst
- [x] Detect event-rate/recon burst
- [x] Detect unusual session duration
- [x] Add explainable campaign clustering from shared evidence (clusters are hypotheses, never attribution)
- [x] Expose baseline/evidence behind every analytic finding
- [x] Add analytics drill-down from charts
- [x] Add analytics regression tests

**Done when:** every anomaly-like finding can be explained from a baseline and concrete measurements.

---

## Cycle K — Detection Engineering & SIEM Interoperability

**Goal:** treat detections as tested, tunable code and let AEGIS feed existing SOC tooling without weakening provenance.

- [x] Add per-rule enable/disable and threshold configuration with validation
- [x] Add time-bounded, audited suppression/allowlist entries (with owner, reason and expiry)
- [x] Add detection backtesting against stored history and the Cycle P replay corpus
- [x] Track per-rule hit counts and analyst closure outcomes (true/false positive rates) — `GET /api/v1/detections/stats`
- [x] Add evidence-backed MITRE ATT&CK coverage view (only techniques supported by implemented rules) — `GET /api/v1/detections/coverage`
- [x] Evaluate Sigma-compatible rule export _(evaluate)_ — see `docs/adr/0001-sigma-rule-export.md` (deferred)
- [x] Document field mapping to ECS and/or OCSF — `docs/SIEM_INTEROP.md`
- [x] Add alert/event forwarding via syslog (RFC 5424) and signed JSON webhook from the collector only
- [x] Keep forwarding bounded (queue limits, retries, back-pressure) and never block ingestion
- [x] Ensure forwarded payloads carry provenance and Evidence Integrity metadata
- [x] Ensure sensors never gain new outbound network paths because of forwarding
- [x] Add forwarding and rule-configuration regression tests

**Done when:** a detection can be tuned, backtested and measured, and its alerts reach an external SIEM with provenance intact.

---

## Cycle G — Cases, Reporting & SOC Workflow

**Goal:** turn cases into complete investigation workspaces and improve operational reporting.

- [x] Add case owner (uses Cycle P operator identities) — defaults to acting operator
- [x] Add case priority
- [x] Add case lifecycle/status
- [x] Add case tags
- [x] Link alerts directly to cases
- [x] Link IOC directly to cases (type=ioc evidence, resolved via the IOC workspace)
- [x] Add unified case timeline — `GET /api/v1/cases/<id>/timeline`
- [x] Separate analyst hypotheses from evidence (dedicated non-factual case field)
- [x] Add case conclusion field
- [x] Add False Positive closure state (alert disposition: true_positive/false_positive/benign)
- [x] Track time-to-acknowledge and time-to-close metrics (MTTA/MTTR) — `GET /api/v1/alerts/metrics`
- [x] Add 24h SOC Summary Report
- [x] Add 7d SOC Summary Report
- [x] Add 30d SOC Summary Report
- [x] Add custom-range SOC Summary Report
- [x] Include Evidence Integrity warnings in summary reports
- [x] Include detections, IOC and MITRE statistics
- [x] Add report redaction profiles (internal vs shareable) — `?profile=shareable`
- [x] Add evidence bundle export with a SHA-256 manifest (chain-of-custody) — `GET /api/v1/reports/case/<id>/bundle.zip`
- [x] Add safe PDF report export — `…/<id>.pdf` (pure-Python, text-only)
- [x] Generate PDFs without rendering attacker-controlled HTML/JS (no headless-browser rendering of raw evidence)
- [x] Add report-generation regression tests

**Done when:** an investigation can start from an alert, become a case and finish with a reproducible evidence-backed report.

---

## Cycle H — Platform Health & Storage

**Goal:** improve operability and prepare AEGIS for larger deployments without sacrificing simple lab installation.

- [x] Add Sensor Health model — `GET /api/v1/sensors/health`
- [x] Alert on sensor silence using Cycle D heartbeats
- [x] Track sensor telemetry gaps and replay rejections from Cycle P
- [x] Track last sensor event
- [x] Track sensor event rate
- [x] Track invalid/rejected sensor events
- [x] Track signature/authentication failures
- [x] Track normalization/evidence-loss metrics — dashboard `data_quality`, SOC summary, `aegis_evidence_*` metrics
- [x] Track database size
- [x] Track storage/retention status
- [x] Add Healthy / Degraded / Critical platform states
- [x] Add Operations/Health dashboard
- [x] Expose operator-authenticated metrics endpoint (Prometheus text format) — `GET /api/v1/metrics`
- [x] Add structured JSON application logs without attacker-controlled log injection — `AEGIS_LOG_FORMAT=json`
- [x] Define explicit load-shedding behavior under disk/ingest pressure and record it as evidence loss
- [x] Add automated backup restore verification — `make verify-restore`
- [x] Define StorageBackend interface — `src/aegis_nexus/storage_backend.py` (runtime-checkable Protocol)
- [x] Refactor SQLite backend behind StorageBackend — `Store` is the reference backend, conformance asserted in tests
- [x] Add optional PostgreSQL backend _(`postgres_backend.PostgresBackend`, psycopg 3, opt-in via the `postgres` extra; SQLite stays default. **All 26 `StorageBackend` contract methods implemented** — event ingest/fetch (jsonb, provenance preserved), counters, cases (CRUD+list+prune+evidence/report/timeline, migration v2 `case_evidence`/`case_history`), heartbeats, nonce anti-replay, health, SQL dashboard, and the full analytics surface (`page_events`, `filter_options`, `detection_context`, `behavioral_context`, sensor telemetry/health). No `PostgresBackendUnsupported` is raised. Verified against real PostgreSQL 16 by the compatibility suite (SQLite+PG) locally and via the CI `postgres:16` service. SQLite-only by design (reported honestly, not faked): per-sensor event sequencing and `session`/`alert` case-evidence kinds — ADR 0002.)_
- [x] Extend the Cycle P migration strategy to PostgreSQL _(`apply_pg_migrations`: forward-only, transactional `schema_migrations` ledger replacing `PRAGMA user_version`, each step under a `pg_advisory_xact_lock` (no double-apply), refusing a newer-than-supported DB with `SchemaVersionError`; verified by `tests/test_postgres_migrations.py` against real PostgreSQL — ADR 0002)_
- [x] Add backend compatibility tests _(behavioural contract suite `tests/test_backend_compatibility.py`: a backend-agnostic, parametrized fixture exercises the `StorageBackend` semantics — provenance-preserving ingest/get round-trip, observable counters, case round-trip, health readiness — green against the reference SQLite backend; a future PostgreSQL backend is wired in by adding one entry to `BACKENDS`. Structural conformance stays in `test_storage_backend.py`.)_
- [x] Document SQLite vs PostgreSQL deployment profiles — `docs/STORAGE.md`

> **PostgreSQL backend implemented** (see `docs/adr/0002-storage-backend-postgresql.md`). The `StorageBackend` interface keeps SQLite (`Store`) as the default reference implementation; the opt-in `PostgresBackend` (psycopg 3) now implements the **full 26-method contract**, with a transactional `schema_migrations` ledger replacing `PRAGMA user_version` and migration v2 adding the `case_evidence`/`case_history` tables for case evidence/report/timeline. Every method is verified against a real PostgreSQL 16 by the parametrized backend-parity suite (`tests/test_backend_compatibility.py`, SQLite+PG) locally and via the CI `postgres:16` service — nothing shipped unverified. SQLite-only by design (reported honestly, never faked): per-sensor event sequencing and `session`/`alert` case-evidence kinds, since the PG core backend models no sessions/alerts domain.

**Done when:** operators can identify degraded sensors/platform components and choose SQLite or PostgreSQL without changing investigation semantics.

---

## Cycle I — Backend Architecture & Maintainability

**Goal:** keep the project maintainable as features grow.

- [x] Split monolithic storage responsibilities into modules _(6 domains extracted to `store_*` mixins/modules; `store.py` ~2400→~940 lines, `Store` remains the composed reference backend — ADR 0003)_
- [x] Separate event storage _(extracted to `store_events.EventStoreMixin` — ADR 0003)_
- [x] Separate session storage _(extracted to `store_sessions.SessionStoreMixin` — ADR 0003)_
- [x] Separate alert storage _(alert logic already lives in the dedicated `alerts.py`, never in the `store.py` monolith)_
- [x] Separate case storage _(extracted to `store_cases.CaseStoreMixin`; `Store` composes it, behaviour unchanged — ADR 0003)_
- [x] Separate analytics storage _(extracted to `store_analytics.AnalyticsStoreMixin`; shared constants in `store_common.py` — ADR 0003)_
- [x] Separate relationship queries _(extracted to `store_relations.py`; `Store.relations` delegates — ADR 0003)_
- [x] Split API routes by domain _(12 domain blueprints via the blueprint-factory pattern — `api_detections`, `api_status`, `api_ips`, `api_activity`, `api_pcap`, `api_iocs`, `api_detection_mgmt`, `api_alerts`, `api_analytics`, `api_cases`, `api_reports`, `api_observability`; `app.py` ~1833→~977 lines. The authenticated ingest/identity core (events, Suricata, quarantine, sensor heartbeat, `/`, `/health`, operator status) stays in the factory by design — ADR 0003)_
- [x] Introduce explicit service layer where useful _(closed by decision — ADR 0003 (2026-11-26): declined, no concrete need (YAGNI). After the storage split (six `store_*` behind `Store`) and the API-route split (12 blueprint factories) the path is already layered (blueprint → composed `Store`/domain helpers); a separate service layer would add indirection without removing any — no cross-blueprint orchestration duplication, no multi-domain transaction, no second caller sharing business logic. Reopen trigger: a second entry point (worker/CLI) reusing blueprint logic, or orchestration duplicated across ≥2 blueprints.)_
- [x] Keep public API behavior backward compatible where practical — guarded by contract tests
- [x] Add schema/migration tests
- [x] Add API contract tests — `tests/test_api_contract.py`
- [x] Add static type checking (e.g. `mypy`) for core modules — gate in `pyproject.toml`, `make typecheck`
- [x] Review frontend module boundaries — documented in `docs/ARCHITECTURE.md` + ADR 0003
- [x] Split `static/app.js` into ES modules by view without adding a mandatory build step _(closed by decision — ADR 0003 (2026-11-26): complete to its by-design boundary. `app.js` is a native ES module (`<script type="module">`, no build step); shared `state`/helpers/network/format live in the leaf module `core.js`; the self-contained views are their own modules: `map.js`, `health.js`, `iocs.js`, `alerts.js`, `audit.js` (cross-view calls inverted via injected hooks). The irreducible coupled core (dashboard, investigate, relations, cases — sharing event/session selection + the refresh orchestrator + the case editor's cross-view evidence) stays in `app.js` by design: splitting it would create a web of cross-view hooks, i.e. worse boundaries, not better. `app.js` ~2516→~1851 lines. Guarded by a browser nav smoke test across every view + the XSS smoke test. Reopen trigger: a refactor of the shared selection model + `refresh()` orchestrator that would let those views become clean leaves — ADR 0003.)_
- [x] Add browser smoke tests (Playwright) including hostile-content XSS fixtures
- [x] Document internal architecture — `docs/ARCHITECTURE.md`

> Lint and dependency/security scanning in CI were moved to Cycle P.

> **Monolith splits adopted incremental extraction** (see `docs/adr/0003-modularization-strategy.md`) and **Cycle I is now complete**. The storage-domain splits (six `store_*` modules behind `Store`) and the API-route-by-domain split (twelve blueprint factories, `app.py` ~1833→~977 lines) were carried out behaviour-preservingly, guarded by the contract tests; the frontend was split to its by-design boundary (`core.js` leaf + five view modules, coupled core in `app.js`). The last two items are **closed by decision** (ADR 0003 update 2026-11-26), each with a reopen trigger: the explicit **service layer is declined** (YAGNI — the blueprint → composed-`Store` path is already layered, no second caller or duplicated orchestration), and the **`app.js` split is complete** (further splitting the coupled dashboard/investigate/relations/cases core would create worse boundaries). A big-bang rewrite of the security-critical monoliths was deliberately never taken. The mypy gate, contract tests, architecture doc and Playwright XSS smoke are in place.

**Done when:** adding a feature no longer requires growing `store.py`, `app.py` or `app.js` as central monoliths.

---

## Cycle J — Study Mode (removed)

**Removed by product decision.** Study Mode (the per-event/session learning
explanations and planned quiz/walkthrough/lab content) has been dropped: the
`study.py` module, the `/api/v1/study/*` endpoints, the console Study view and
its tests and strings were removed. AEGIS-NEXUS keeps its focus on SOC
analysis, evidence and threat research rather than a built-in learning mode. If
a learning layer is wanted later it should be reintroduced as a separate,
clearly-scoped effort.

---

## Cycle L — Geospatial Attack Visualization

**Goal:** evolve the existing flat SVG Attack Map into an interactive, live world view that shows attack origins as glowing points, without implying attribution and without adding any outbound network path.

**Note:** builds on the completed offline GeoIP/ASN enrichment and the existing Attack Map panel. Geographic origin is enrichment-derived and approximate; it is never presented as actor attribution (VPN/proxy/Tor caveat), consistent with the project non-goals.

- [x] Design a geo-aggregation API that returns approximate origin points with counts over the active time window, reusing operator-key auth, global filters and search
- [x] Mark every point's provenance explicitly as Enrichment/Derived and surface the GeoIP accuracy radius
- [x] Aggregate points server-side with a hard point cap and bounded payload size
- [x] Add an explicit "unmapped" bucket for private, non-global or non-geolocatable IPs and record it as evidence completeness, never a silent drop
- [x] Vendor the visualization library and base world asset locally — no CDN and no online tile/map servers (CSP stays `script-src 'self'` / `connect-src 'self'`)
- [x] Render attack origins as intensity-scaled glowing points (event/session count and severity map to size and brightness)
- [x] Provide a 2D flat-map fallback when 3D/WebGL is unavailable
- [x] Add live updates over a same-origin stream (SSE) or bounded polling, with an explicit live/pause toggle
- [x] Honor `prefers-reduced-motion` with a static, non-pulsing fallback
- [x] Make points interactive: hover/focus shows an escaped tooltip (approximate location, country, ASN/organization, session/event counts, accuracy radius); selecting a point filters the dashboard or opens IP investigation
- [x] Display a persistent caveat that geographic origin is approximate and is not actor attribution
- [x] Keep every attacker-controlled field escaped in tooltips and labels
- [x] Add keyboard navigation and a screen-reader data-table equivalent of the top origins, and update `ACCESSIBILITY.md`
- [x] Provide IT/EN strings for all new labels, the live/pause control and the attribution caveat
- [x] Add tests for malformed/partial coordinates, missing geo, the point cap, the unmapped bucket and tooltip escaping of hostile input
- [x] Reflect any new live-stream data flow in `docs/THREAT_MODEL.md` and privacy documentation

**Done when:** analysts can watch attack origins update live on an interactive globe, with approximate geolocation clearly labelled as enrichment rather than attribution, no new outbound paths, and full IT/EN and accessibility parity.

---

## Cross-cutting requirements

These requirements apply to **every** roadmap cycle.

- [x] Preserve Observed / Enrichment / Derived / Hypotheses separation _(guarded by `test_model.py`, `test_api_contract.py`, `test_store.py`)_
- [x] Preserve explicit collector/sensor provenance _(guarded by `test_operations.py` (collector_received_at vs sensor time), `test_model.py`)_
- [x] Never invent Threat Intelligence, CVE or MITRE mappings _(guarded by `test_model.py` (`test_mitre_mapping_requires_evidence`, `test_ioc_requires_explicit_evidence`))_
- [x] Never infer human or threat-actor attribution from infrastructure alone _(guarded by `test_enrichment.py` (GeoIP as external enrichment), `test_detection.py` (credential reuse without attribution), `test_fingerprints.py`)_
- [x] Treat every captured value as hostile input _(guarded by `test_security.py`, `test_sensors.py` (bounding/oversize/reject), `test_derivation.py`)_
- [x] Keep attacker-controlled content escaped in the UI and reports _(guarded by `test_frontend_safety.py`, `test_browser_smoke.py`, `test_reporting.py`, `test_pdf_report.py`, `test_app.py` (CSV formula-injection))_
- [x] Keep credential handling privacy-aware and secret-safe _(guarded by `test_redaction.py`, `test_correlation_workspace.py`, `test_sensor_plugins.py`, `test_detection.py` (honeytoken))_
- [x] Keep collection and retention bounded _(guarded by `test_store.py` (retention/capacity by receive time), `test_collector_counters.py` (load shedding), `test_pcap.py`)_
- [x] Maintain sensor isolation and egress restrictions _(guarded by `test_sensor_safety.py` (egress guard), `test_sensors.py`/`test_sensor_plugins.py` (never executes input))_
- [x] Maintain IT/EN interface parity _(guarded by `test_frontend_safety.py` (`test_frontend_i18n_covers_template_and_literal_translation_keys`))_
- [ ] Add tests for every security-sensitive feature _(continuous practice (not a one-off artifact) — upheld by the 418-test suite; every security feature ships with its test)_
- [ ] Keep documentation synchronized with implementation _(continuous practice — code/test/docs land together; `docs/` kept in lockstep)_
- [ ] Keep CI green before marking an implementation item complete _(CI restored — `.github/workflows/ci.yml`; continuous process practice: keep it green before completing an item)_
- [ ] Update the threat model for every new attack surface or data flow _(continuous practice — `docs/THREAT_MODEL.md` updated per new data flow)_
- [x] Never add outbound network paths from sensors _(guarded by `test_sensor_safety.py` (egress guard covers every built-in exposure network))_
- [x] Record every drop, truncation, rejection or load-shedding decision as evidence loss _(guarded by `test_sensor_sequence.py` (rejected/dropped counted as loss), `test_sensors.py` (truncation disclosed), `test_collector_counters.py`)_
- [x] Keep ingest performance within documented bounds (add a benchmark when touching the hot path) _(benchmark added — `test_ingest_performance.py` guards the normalize_event hot path against gross regression)_
- [x] Keep operator actions auditable once Cycle P audit logging exists _(audit logging exists (`operator_audit.py`); guarded by `test_operator_audit.py` (lifecycle/case/export audited, auth required, note bodies not copied))_

> Cross-cutting requirements are checked **when a concrete code+test guard enforces them** (closure by evidence): 14/18 are ticked above with the guarding test(s). The remaining four — "add tests for every security feature", "keep docs synchronized", "keep CI green", "update the threat model" — stay unchecked on purpose: they are continuous *process* practices, not one-time artifacts, so they are never "done". A regression in any ticked invariant fails its guard test in the suite.

---

## Current implementation priority

1. **Cycle P — Platform Readiness & Integrity Hardening** (gate for new schema fields, new sensors and Cycle G)
2. **Cycle D — Sensor Platform & Honeypot Expansion** (remaining items)
3. **Cycle C — Network Evidence & Visibility** (extension items)
4. **Cycle E — Threat Intelligence & CTI**
5. **Cycle F — Behavioral Analytics**
6. **Cycle K — Detection Engineering & SIEM Interoperability**
7. **Cycle G — Cases, Reporting & SOC Workflow**
8. **Cycle H — Platform Health & Storage**
9. **Cycle I — Backend Architecture & Maintainability**
11. **Cycle L — Geospatial Attack Visualization** (UX enhancement; can be pulled forward independently)

> Cycle I work may be pulled forward opportunistically: when a cycle touches `store.py`, `app.py` or `app.js`, extract the touched domain into its own module instead of growing the monolith.

### Dependencies

| Cycle | Depends on |
|---|---|
| P | — |
| C | P (migrations, replay corpus) |
| D | P (sequence numbers, audit log); C (network-evidence schema) |
| E | P (migrations) |
| F | P (replay corpus); C/D for network and new-sensor baselines |
| K | A (detections); P (audit log, replay corpus) |
| G | P (operator identities); K (closure outcomes) |
| H | P (gap/replay metrics); D (heartbeats) |
| I | P (lint/type tooling) |
| L | Foundation (GeoIP/ASN enrichment, Attack Map); optionally C (network evidence for richer tooltips) |

---

## Progress

| Cycle | Status |
|---|---|
| Foundation | ✅ Completed |
| A — SOC Detection & Alerting | ✅ Completed |
| B — Correlation & Investigation 2.0 | ✅ Completed |
| P — Platform Readiness & Integrity Hardening | ✅ 20/20 · CI restored with lint/SAST/dep-audit/secret-scan/Trivy/SBOM + hash-locked builds; all CI actions pinned to immutable commit SHAs (`# vX.Y.Z` comments) with Dependabot bumping them |
| C — Network Evidence & Visibility | 🟨 25/26 · SSH client version + KEXINIT offer lists + native **HASSH** captured (`observed.network.ssh`, bounded, tooling hint); dedicated **PCAP capture sidecars** shipped as an opt-in overlay (per-decoy netns-sharing, `CAP_NET_RAW` in sidecar only, BPF-scoped, ring-buffered, CI isolation-checked); JA4+ licence evaluated (ADR 0005: JA4/TLS BSD-3 permitted, JA4H & other FoxIO-1.1 methods declined — GPLv3-incompatible + patent-pending, use Suricata/Zeek ingestion). Only remaining: native JA4 TLS (low-priority, Suricata covers it) — ADR 0004/0005 |
| D — Sensor Platform & Honeypot Expansion | ✅ Completed |
| E — Threat Intelligence & CTI | ✅ Completed |
| F — Behavioral Analytics | ✅ Completed |
| K — Detection Engineering & SIEM Interoperability | ✅ Completed |
| G — Cases, Reporting & SOC Workflow | ✅ Completed |
| H — Platform Health & Storage | ✅ 22/22 · optional PostgreSQL backend now implements the **full `StorageBackend` contract** (all 26 methods, incl. case evidence/report/timeline via migration v2) + versioned migration ledger, verified cross-backend against real PostgreSQL 16 (ADR 0002); PG is a drop-in except per-sensor sequencing and session/alert case-evidence, SQLite-only by design |
| I — Backend Architecture & Maintainability | ✅ 17/17 · storage split done (6 domains in `store_*`); API-route split done (12 domain blueprints, `app.py` ~1833→~977 lines; authenticated ingest/identity core stays in the factory by design); frontend split to its by-design boundary (`core.js` leaf + 5 view modules; coupled core in `app.js`); service layer **closed by decision** (YAGNI, no concrete need) — both closures recorded with reopen triggers in ADR 0003 |
| J — Study Mode | ❌ Removed |
| L — Geospatial Attack Visualization | ✅ Completed |

---

© Chiara Berti — 2026
