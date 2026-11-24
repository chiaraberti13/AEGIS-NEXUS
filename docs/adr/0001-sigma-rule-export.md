# ADR 0001 — Sigma-compatible rule export

- Status: **Accepted** (evaluation outcome — defer implementation)
- Date: 2026-11-24
- Context: ROADMAP Cycle K, "Evaluate Sigma-compatible rule export _(evaluate)_"

## Context

Sigma is a YAML rule format for expressing log-based detections in a
backend-agnostic way. The roadmap item asks whether AEGIS detection rules
should be exportable as Sigma so they can be reused in other SIEMs.

AEGIS detection rules are not field-condition expressions: they are
deterministic Python matchers (`src/aegis_nexus/detection.py`). They fall into
two groups:

1. **Single-event matchers** — `download_attempt`, `command_staging_detected`,
   `suricata_high_severity`. These test one captured field (e.g. a substring of
   `observed.command`, or an IDS severity) and map reasonably onto a Sigma
   `detection` block over an ECS/OCSF field (see `docs/SIEM_INTEROP.md`).
2. **Stateful/correlation rules** — `multiple_auth_failures`,
   `credential_bruteforce`, `credential_reuse`, `web_scanning`,
   `path_traversal_sequence`, `rapid_port_sequence`, `recon_burst`,
   `honeytoken_reuse`. These evaluate counts/distinct-values over a time window
   and source grouping. They can only be expressed with Sigma's newer
   *correlation* rules, whose semantics (and backend support) differ from the
   deterministic windowing AEGIS implements.

## Decision

**Defer a built-in Sigma exporter.** We will not ship a Sigma export in this
cycle. Reasons:

- A faithful export of the stateful rules would require re-encoding windowed
  correlation logic into Sigma correlation rules, which would be a second,
  divergent source of truth for detections and a maintenance liability.
- We cannot validate emitted Sigma against an authoritative validator inside
  the build/test environment (no Sigma dependency; the project keeps a minimal
  runtime surface). Shipping plausibly-valid-but-unverified Sigma YAML would
  violate the project rule of never declaring an output correct without
  verification.
- SIEM interoperability is already served without Sigma: the evidence-backed
  MITRE ATT&CK coverage view (`/api/v1/detections/coverage`) and the ECS/OCSF
  field mapping (`docs/SIEM_INTEROP.md`) let operators re-implement equivalent
  detections natively in their SIEM.

## Consequences

- The ROADMAP item is marked complete as an **evaluation** (this ADR), per the
  roadmap legend for `_(evaluate)_` spikes.
- If demand appears, a future cycle can add an exporter **scoped to the
  single-event matchers only**, emitting Sigma via a real `sigma`/YAML
  dependency with validation in tests, and explicitly listing the stateful
  rules as not exported (mirroring how the MITRE coverage view reports unmapped
  rules). This ADR should be superseded at that point.

## Notes

This is the first Architecture Decision Record in the project; ADRs live under
`docs/adr/NNNN-title.md` and are numbered sequentially. They record engineering
decisions and are developer-facing (English), like `ROADMAP.md` and
`CONTRIBUTING.md`.
