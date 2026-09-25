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
- [x] Study Mode
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

**Why first:** new schema fields, new sensors and Cycle G analyst identity all build on this cycle. Schema changes now go through versioned migrations (`src/aegis_nexus/migrations.py`); signed sensor requests are deduplicated only by event ID (there is no per-request nonce), and all analysts share one operator key.

### Schema & data lifecycle
- [x] Add versioned, forward-only SQLite schema migrations (`PRAGMA user_version`)
- [ ] Take an automatic online backup before applying migrations
- [ ] Add migration tests from every previously released schema version
- [ ] Add a versioned synthetic attack-replay corpus (SSH/Web/FTP/Telnet/Suricata fixtures) for regression tests in later cycles

### Sensor trust & evidence integrity
- [ ] Add sensor replay protection (per-sensor nonce/sequence cache bounded to the signature skew window)
- [ ] Add per-sensor monotonic sequence numbers to detect telemetry gaps as evidence loss
- [ ] Add a tamper-evident hash chain over stored events (`prev_hash` / `record_hash`)
- [ ] Add an offline integrity-verification command for the event hash chain and backups
- [ ] Document zero-downtime rotation of sensor and operator secrets (overlapping keys)

### Operator accountability
- [ ] Support multiple named operator identities (per-analyst keys) while keeping the single-key lab mode
- [ ] Add an append-only operator audit log (alert lifecycle, case changes, exports, PCAP/artifact access)
- [ ] Surface the audit log in the UI and in case reports

### Supply chain & CI security
- [ ] Add lint/format checks to CI (e.g. `ruff`)
- [ ] Add dependency vulnerability scanning to CI (e.g. `pip-audit`)
- [ ] Add Python SAST to CI (e.g. `bandit`) with a reviewed baseline
- [ ] Add secret scanning to CI (e.g. `gitleaks`)
- [ ] Add container image vulnerability scanning (e.g. Trivy) for the built image
- [ ] Generate an SBOM (CycloneDX) for each build
- [ ] Pin GitHub Actions by commit SHA and enable automated dependency updates
- [ ] Add hash-locked dependency constraints for reproducible container builds

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
- [ ] Capture SSH client version string and KEX/cipher offer lists
- [ ] Add HASSH-style SSH client fingerprints (fingerprint = tooling hint, never identity)
- [ ] Add HTTP client fingerprints (e.g. JA4H) after licence review
- [x] Add optional TLS metadata/fingerprints where technically available
- [ ] Add sensor-native JA4 TLS fingerprints (Suricata JA3/JA3S/JA4 passthrough already exists; review JA4+ licence terms before adoption)
- [x] Add DNS indicator evidence where available
- [x] Design optional passive fingerprint provider interface
- [ ] Evaluate optional Zeek log ingestion (`conn`, `http`, `ssh`, `dns`) with the same provenance model as Suricata _(evaluate)_
- [x] Add optional bounded PCAP capture mode
- [ ] Run PCAP capture in a dedicated capture container (`CAP_NET_RAW` only, never inside decoys)
- [ ] Restrict capture with BPF filters to decoy ports/interfaces
- [ ] Use ring-buffer capture so disk usage has a hard upper bound
- [x] Add PCAP size limits
- [x] Add PCAP retention limits
- [x] Hash retained PCAP evidence with SHA-256
- [x] Associate PCAP evidence with session IDs
- [ ] Serve PCAP only as authenticated, audited attachment downloads (never parsed or rendered in the browser)
- [x] Add Network Evidence investigation panel
- [x] Add network-evidence security/privacy documentation
- [x] Add bounded-capture and hostile-input tests

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
- [ ] Evaluate PostgreSQL decoy
- [ ] Evaluate RDP handshake decoy
- [ ] Evaluate VNC decoy
- [ ] Evaluate SNMP decoy
- [ ] Add generic TCP banner decoy
- [ ] Evaluate read-only Modbus/TCP ICS decoy _(evaluate)_
- [ ] Add honeytokens/canary credentials planted in decoy content
- [ ] Raise high-fidelity alerts when a planted honeytoken is reused on any sensor
- [ ] Capture attacker uploads (FTP `STOR`, web uploads, SSH `scp`/`sftp` where emulated) into an inert quarantine store
- [ ] Hash quarantined artifacts (SHA-256), enforce size/count limits and never serve them inline
- [ ] Verify IPv6 listening, normalization and egress-guard coverage for every sensor
- [ ] Ensure new decoys never execute attacker-supplied commands/payloads
- [ ] Add isolation and hostile-input tests for every sensor
- [ ] Document how to build third-party/custom sensors

**Done when:** a new protocol decoy can be added through the sensor interface without modifying the collector core.

---

## Cycle E — Threat Intelligence & CTI

**Goal:** turn enrichment into a provider-based CTI layer while preserving source provenance.

- [ ] Define Threat Intelligence provider interface
- [ ] Migrate Local JSON Threat Context to provider interface
- [ ] Store provider/source/retrieval timestamp for every enrichment
- [ ] Store confidence only when supplied by the source
- [ ] Add indicator validity windows where available
- [ ] Add feed/provider health information
- [ ] Add STIX 2.x export
- [ ] Add STIX 2.x import
- [ ] Evaluate TAXII client support
- [ ] Add configurable custom-feed adapter
- [ ] Evaluate MISP export/import _(evaluate)_
- [ ] Add TLP markings and sharing policy to CTI exports
- [ ] Strip sensor-internal data (management IPs, sensor secrets, operator notes) from shareable exports
- [ ] Add indicator aging/decay without deleting historical evidence
- [ ] Add benign-scanner context lists as enrichment (never as silent suppression)
- [ ] Keep observed telemetry separate from Threat Intelligence
- [ ] Prevent TI matches from automatically creating attribution
- [ ] Prevent TI matches from inventing MITRE/CVE relationships
- [ ] Add CTI provenance tests
- [ ] Document provider trust and enrichment limitations

**Done when:** every intelligence assertion is attributable to a named source and timestamp and remains separate from observed evidence.

---

## Cycle F — Behavioral Analytics

**Goal:** identify noteworthy changes and bursts using explainable deterministic analytics before considering ML/AI.

- [ ] Implement baseline framework
- [ ] Add minimum-sample thresholds so cold-start baselines do not produce findings
- [ ] Add 24-hour baseline
- [ ] Add 7-day baseline
- [ ] Add 30-day baseline
- [ ] Detect new source IP
- [ ] Detect new country
- [ ] Detect new ASN
- [ ] Detect new username
- [ ] Detect new payload hash
- [ ] Detect new URL/domain
- [ ] Detect rare command
- [ ] Detect command-frequency spike
- [ ] Detect authentication-attempt burst
- [ ] Detect event-rate/recon burst
- [ ] Detect unusual session duration
- [ ] Add explainable campaign clustering from shared evidence (clusters are hypotheses, never attribution)
- [ ] Expose baseline/evidence behind every analytic finding
- [ ] Add analytics drill-down from charts
- [ ] Add analytics regression tests

**Done when:** every anomaly-like finding can be explained from a baseline and concrete measurements.

---

## Cycle K — Detection Engineering & SIEM Interoperability

**Goal:** treat detections as tested, tunable code and let AEGIS feed existing SOC tooling without weakening provenance.

- [ ] Add per-rule enable/disable and threshold configuration with validation
- [ ] Add time-bounded, audited suppression/allowlist entries (with owner, reason and expiry)
- [ ] Add detection backtesting against stored history and the Cycle P replay corpus
- [ ] Track per-rule hit counts and analyst closure outcomes (true/false positive rates)
- [ ] Add evidence-backed MITRE ATT&CK coverage view (only techniques supported by implemented rules)
- [ ] Evaluate Sigma-compatible rule export _(evaluate)_
- [ ] Document field mapping to ECS and/or OCSF
- [ ] Add alert/event forwarding via syslog (RFC 5424) and signed JSON webhook from the collector only
- [ ] Keep forwarding bounded (queue limits, retries, back-pressure) and never block ingestion
- [ ] Ensure forwarded payloads carry provenance and Evidence Integrity metadata
- [ ] Ensure sensors never gain new outbound network paths because of forwarding
- [ ] Add forwarding and rule-configuration regression tests

**Done when:** a detection can be tuned, backtested and measured, and its alerts reach an external SIEM with provenance intact.

---

## Cycle G — Cases, Reporting & SOC Workflow

**Goal:** turn cases into complete investigation workspaces and improve operational reporting.

- [ ] Add case owner (uses Cycle P operator identities)
- [ ] Add case priority
- [ ] Add case lifecycle/status
- [ ] Add case tags
- [ ] Link alerts directly to cases
- [ ] Link IOC directly to cases
- [ ] Add unified case timeline
- [ ] Separate analyst hypotheses from evidence
- [ ] Add case conclusion field
- [ ] Add False Positive closure state
- [ ] Track time-to-acknowledge and time-to-close metrics (MTTA/MTTR)
- [ ] Add 24h SOC Summary Report
- [ ] Add 7d SOC Summary Report
- [ ] Add 30d SOC Summary Report
- [ ] Add custom-range SOC Summary Report
- [ ] Include Evidence Integrity warnings in summary reports
- [ ] Include detections, IOC and MITRE statistics
- [ ] Add report redaction profiles (internal vs shareable)
- [ ] Add evidence bundle export with a SHA-256 manifest (chain-of-custody)
- [ ] Add safe PDF report export
- [ ] Generate PDFs without rendering attacker-controlled HTML/JS (no headless-browser rendering of raw evidence)
- [ ] Add report-generation regression tests

**Done when:** an investigation can start from an alert, become a case and finish with a reproducible evidence-backed report.

---

## Cycle H — Platform Health & Storage

**Goal:** improve operability and prepare AEGIS for larger deployments without sacrificing simple lab installation.

- [ ] Add Sensor Health model
- [ ] Alert on sensor silence using Cycle D heartbeats
- [ ] Track sensor telemetry gaps and replay rejections from Cycle P
- [ ] Track last sensor event
- [ ] Track sensor event rate
- [ ] Track invalid/rejected sensor events
- [ ] Track signature/authentication failures
- [ ] Track normalization/evidence-loss metrics
- [ ] Track database size
- [ ] Track storage/retention status
- [ ] Add Healthy / Degraded / Critical platform states
- [ ] Add Operations/Health dashboard
- [ ] Expose operator-authenticated metrics endpoint (Prometheus text format)
- [ ] Add structured JSON application logs without attacker-controlled log injection
- [ ] Define explicit load-shedding behavior under disk/ingest pressure and record it as evidence loss
- [ ] Add automated backup restore verification
- [ ] Define StorageBackend interface
- [ ] Refactor SQLite backend behind StorageBackend
- [ ] Add optional PostgreSQL backend
- [ ] Extend the Cycle P migration strategy to PostgreSQL
- [ ] Add backend compatibility tests
- [ ] Document SQLite vs PostgreSQL deployment profiles

**Done when:** operators can identify degraded sensors/platform components and choose SQLite or PostgreSQL without changing investigation semantics.

---

## Cycle I — Backend Architecture & Maintainability

**Goal:** keep the project maintainable as features grow.

- [ ] Split monolithic storage responsibilities into modules
- [ ] Separate event storage
- [ ] Separate session storage
- [ ] Separate alert storage
- [ ] Separate case storage
- [ ] Separate analytics storage
- [ ] Separate relationship queries
- [ ] Split API routes by domain
- [ ] Introduce explicit service layer where useful
- [ ] Keep public API behavior backward compatible where practical
- [ ] Add schema/migration tests
- [ ] Add API contract tests
- [ ] Add static type checking (e.g. `mypy`) for core modules
- [ ] Review frontend module boundaries
- [ ] Split `static/app.js` into ES modules by view without adding a mandatory build step
- [ ] Add browser smoke tests (Playwright) including hostile-content XSS fixtures
- [ ] Document internal architecture

> Lint and dependency/security scanning in CI were moved to Cycle P.

**Done when:** adding a feature no longer requires growing `store.py`, `app.py` or `app.js` as central monoliths.

---

## Cycle J — Study Mode 2.0

**Goal:** make real captured evidence usable as a structured SOC learning environment.

- [ ] Add event-type-specific learning explanations
- [ ] Add alert-specific learning explanations
- [ ] Explain why a detection fired
- [ ] Explain observed vs enrichment vs derived vs hypothesis
- [ ] Explain explicit vs heuristic correlation
- [ ] Explain evidence completeness/truncation limitations
- [ ] Add session investigation walkthroughs
- [ ] Add Suricata-focused walkthroughs
- [ ] Add credential-attack walkthroughs
- [ ] Add command/payload investigation walkthroughs
- [ ] Add network-evidence walkthroughs
- [ ] Add evidence-based quiz mode
- [ ] Generate questions only from stored evidence/context
- [ ] Explain every quiz answer
- [ ] Add offline Lab Mode seeded from the synthetic replay corpus (no live exposure required)
- [ ] Add CTF-style guided exercises with verifiable answers from stored evidence
- [ ] Add pseudonymized study/classroom exports (hide real source IPs and usernames)
- [ ] Add IT/EN parity tests for Study Mode content

**Done when:** a learner can investigate a real AEGIS event/session and understand both the technical evidence and the SOC reasoning process.

---

## Cross-cutting requirements

These requirements apply to **every** roadmap cycle.

- [ ] Preserve Observed / Enrichment / Derived / Hypotheses separation
- [ ] Preserve explicit collector/sensor provenance
- [ ] Never invent Threat Intelligence, CVE or MITRE mappings
- [ ] Never infer human or threat-actor attribution from infrastructure alone
- [ ] Treat every captured value as hostile input
- [ ] Keep attacker-controlled content escaped in the UI and reports
- [ ] Keep credential handling privacy-aware and secret-safe
- [ ] Keep collection and retention bounded
- [ ] Maintain sensor isolation and egress restrictions
- [ ] Maintain IT/EN interface parity
- [ ] Add tests for every security-sensitive feature
- [ ] Keep documentation synchronized with implementation
- [ ] Keep CI green before marking an implementation item complete
- [ ] Update the threat model for every new attack surface or data flow
- [ ] Never add outbound network paths from sensors
- [ ] Record every drop, truncation, rejection or load-shedding decision as evidence loss
- [ ] Keep ingest performance within documented bounds (add a benchmark when touching the hot path)
- [ ] Keep operator actions auditable once Cycle P audit logging exists

> Cross-cutting requirements remain unchecked here because they are continuous constraints, not one-time milestones.

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
10. **Cycle J — Study Mode 2.0**

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
| J | P (replay corpus); A–G content to explain |

---

## Progress

| Cycle | Status |
|---|---|
| Foundation | ✅ Completed |
| A — SOC Detection & Alerting | ✅ Completed |
| B — Correlation & Investigation 2.0 | ✅ Completed |
| P — Platform Readiness & Integrity Hardening | 🟨 In progress |
| C — Network Evidence & Visibility | 🟨 Core completed · extensions planned |
| D — Sensor Platform & Honeypot Expansion | 🟨 In progress |
| E — Threat Intelligence & CTI | ⬜ Planned |
| F — Behavioral Analytics | ⬜ Planned |
| K — Detection Engineering & SIEM Interoperability | ⬜ Planned |
| G — Cases, Reporting & SOC Workflow | ⬜ Planned |
| H — Platform Health & Storage | ⬜ Planned |
| I — Backend Architecture & Maintainability | ⬜ Planned |
| J — Study Mode 2.0 | ⬜ Planned |

---

© Chiara Berti — 2026
