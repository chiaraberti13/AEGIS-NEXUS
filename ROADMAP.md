# 🛡️ AEGIS-NEXUS Roadmap

> Development roadmap for evolving AEGIS-NEXUS into a modern **Honeypot + SOC Analysis + Threat Research + Cybersecurity Learning Lab**.

This document is the project's implementation checklist. Items are checked only after the feature is implemented, tested and integrated without weakening evidence provenance, sensor isolation, privacy or hostile-input handling.

**Legend:** `[ ]` planned · `[x]` completed

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

- [ ] Extend correlation across IP, session, username and credential fingerprint
- [ ] Correlate commands, payload hashes, URLs, domains and other IOC
- [ ] Correlate ports, services, ASN and Suricata alerts
- [ ] Introduce explainable correlation scoring
- [ ] Store correlation method, score and evidence basis
- [ ] Prevent correlation score from being presented as attribution
- [x] Add IOC Workspace
- [x] Add IOC first-seen / last-seen / occurrence statistics
- [x] Link IOC to sessions, source IPs, sensors, alerts and cases
- [ ] Add IOC search/filter/export
- [ ] Upgrade Relationship Graph with node-type filters
- [ ] Add on-demand graph expansion
- [ ] Add graph depth controls
- [ ] Add evidence-only graph mode
- [ ] Add provenance cues to graph nodes/edges
- [ ] Add graph side inspector
- [ ] Add evidence-path highlighting
- [ ] Add Find Path between two investigation entities
- [ ] Add graph/correlation regression tests

**Done when:** an analyst can move from an alert or IOC to all supporting evidence and understand exactly why each relationship exists.

---

## Cycle C — Network Evidence & Visibility

**Goal:** add network-level context while keeping collection bounded and privacy-aware.

- [ ] Define network-evidence schema and provenance
- [ ] Capture connection duration
- [ ] Capture bytes in/out where sensors can observe them
- [ ] Capture packet/connection counters where available
- [ ] Capture relevant TCP metadata without claiming unsupported OS attribution
- [ ] Improve HTTP header and User-Agent evidence
- [ ] Add optional TLS metadata/fingerprints where technically available
- [ ] Add DNS indicator evidence where available
- [ ] Design optional passive fingerprint provider interface
- [ ] Add optional bounded PCAP capture mode
- [ ] Add PCAP size limits
- [ ] Add PCAP retention limits
- [ ] Hash retained PCAP evidence with SHA-256
- [ ] Associate PCAP evidence with session IDs
- [ ] Add Network Evidence investigation panel
- [ ] Add network-evidence security/privacy documentation
- [ ] Add bounded-capture and hostile-input tests

**Done when:** network evidence enriches investigations without creating unlimited packet retention or unsupported attribution.

---

## Cycle D — Sensor Platform & Honeypot Expansion

**Goal:** make sensors modular and add new emulated attack surfaces safely.

- [ ] Define common Sensor interface
- [ ] Implement sensor registry
- [ ] Move existing SSH sensor to plugin architecture
- [ ] Move existing Web sensor to plugin architecture
- [ ] Move existing FTP/Telnet sensors to plugin architecture
- [ ] Add declarative sensor configuration
- [ ] Add sensor capability metadata
- [ ] Add SMTP decoy
- [ ] Add Redis decoy
- [ ] Add MySQL decoy
- [ ] Add SMB decoy
- [ ] Evaluate PostgreSQL decoy
- [ ] Evaluate RDP handshake decoy
- [ ] Evaluate VNC decoy
- [ ] Evaluate SNMP decoy
- [ ] Add generic TCP banner decoy
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
- [ ] Expose baseline/evidence behind every analytic finding
- [ ] Add analytics drill-down from charts
- [ ] Add analytics regression tests

**Done when:** every anomaly-like finding can be explained from a baseline and concrete measurements.

---

## Cycle G — Cases, Reporting & SOC Workflow

**Goal:** turn cases into complete investigation workspaces and improve operational reporting.

- [ ] Add case owner
- [ ] Add case priority
- [ ] Add case lifecycle/status
- [ ] Add case tags
- [ ] Link alerts directly to cases
- [ ] Link IOC directly to cases
- [ ] Add unified case timeline
- [ ] Separate analyst hypotheses from evidence
- [ ] Add case conclusion field
- [ ] Add False Positive closure state
- [ ] Add 24h SOC Summary Report
- [ ] Add 7d SOC Summary Report
- [ ] Add 30d SOC Summary Report
- [ ] Add custom-range SOC Summary Report
- [ ] Include Evidence Integrity warnings in summary reports
- [ ] Include detections, IOC and MITRE statistics
- [ ] Add safe PDF report export
- [ ] Add report-generation regression tests

**Done when:** an investigation can start from an alert, become a case and finish with a reproducible evidence-backed report.

---

## Cycle H — Platform Health & Storage

**Goal:** improve operability and prepare AEGIS for larger deployments without sacrificing simple lab installation.

- [ ] Add Sensor Health model
- [ ] Track last sensor event
- [ ] Track sensor event rate
- [ ] Track invalid/rejected sensor events
- [ ] Track signature/authentication failures
- [ ] Track normalization/evidence-loss metrics
- [ ] Track database size
- [ ] Track storage/retention status
- [ ] Add Healthy / Degraded / Critical platform states
- [ ] Add Operations/Health dashboard
- [ ] Define StorageBackend interface
- [ ] Refactor SQLite backend behind StorageBackend
- [ ] Add optional PostgreSQL backend
- [ ] Add database migration/version strategy
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
- [ ] Add static/lint checks to CI
- [ ] Add dependency/security scanning to CI
- [ ] Review frontend module boundaries
- [ ] Document internal architecture

**Done when:** adding a feature no longer requires growing `store.py` or `app.py` as central monoliths.

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

> Cross-cutting requirements remain unchecked here because they are continuous constraints, not one-time milestones.

---

## Current implementation priority

1. **Cycle A — SOC Detection & Alerting**
2. **Cycle B — Correlation & Investigation 2.0**
3. **Cycle C — Network Evidence & Visibility**
4. **Cycle D — Sensor Platform & Honeypot Expansion**
5. **Cycle E — Threat Intelligence & CTI**
6. **Cycle F — Behavioral Analytics**
7. **Cycle G — Cases, Reporting & SOC Workflow**
8. **Cycle H — Platform Health & Storage**
9. **Cycle I — Backend Architecture & Maintainability**
10. **Cycle J — Study Mode 2.0**

---

## Progress

| Cycle | Status |
|---|---|
| Foundation | ✅ Completed |
| A — SOC Detection & Alerting | ✅ Completed |
| B — Correlation & Investigation 2.0 | 🟨 In progress |
| C — Network Evidence & Visibility | ⬜ Planned |
| D — Sensor Platform & Honeypot Expansion | ⬜ Planned |
| E — Threat Intelligence & CTI | ⬜ Planned |
| F — Behavioral Analytics | ⬜ Planned |
| G — Cases, Reporting & SOC Workflow | ⬜ Planned |
| H — Platform Health & Storage | ⬜ Planned |
| I — Backend Architecture & Maintainability | ⬜ Planned |
| J — Study Mode 2.0 | ⬜ Planned |

---

© Chiara Berti — 2026
