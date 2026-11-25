# ADR 0005 — Cycle C remaining items: client fingerprints and dedicated PCAP capture

- Status: **Accepted** (decisions recorded; items implemented on demand / when unblocked)
- Date: 2026-11-24
- Context: the remaining open Cycle C ("Network Evidence & Visibility") items:
  SSH client version + KEX/cipher offers and HASSH fingerprints; HTTP (JA4H)
  and TLS (JA4) fingerprints; and dedicated-container PCAP capture (BPF,
  ring-buffer).

## Decision

Each remaining item is decided here so none is left dangling. None is shipped
unverified or over a boundary the project forbids.

### SSH client version + KEX/cipher offers, HASSH — implement on demand

The SSH client **version string** is readily available server-side
(`paramiko.Transport.remote_version`). The full client **KEX/cipher/MAC/
compression offer lists** needed for a HASSH fingerprint are parsed by paramiko
during negotiation but are not exposed through a stable public API, so a HASSH
implementation would depend on paramiko internals and be version-fragile.

Decision: defer until it can be done without relying on private paramiko state
(e.g. a thin, well-tested KEXINIT capture hook, or a paramiko release that
exposes the offers). When implemented, the fingerprint is a **tooling hint,
never identity**, recorded as `observed`/`observed.network` with provenance and
bounded hostile-input handling, with isolation and mapping tests.

### HTTP (JA4H) and TLS (JA4) fingerprints — blocked pending licence review

JA4+ fingerprints carry licence terms that must be reviewed before adoption
(the ROADMAP already flags this). This is a product/legal decision, not an
engineering one. Decision: **blocked** until the maintainer completes the
licence review. Suricata JA3/JA3S/JA4 passthrough already exists for deployments
that need TLS fingerprints today.

### Dedicated-container PCAP capture (BPF, ring-buffer) — deployment infrastructure

Bounded PCAP capture already exists in-app (size/retention limits, SHA-256,
session association, authenticated+audited attachment download — ADR-adjacent,
done). Running capture in a **dedicated container** with `CAP_NET_RAW` only
(never inside a decoy), restricted by BPF to decoy ports, with a ring-buffer
hard disk cap, is deployment/infrastructure work that requires a privileged
capture sidecar and cannot be built or verified inside this project's unit-test
environment. Decision: provide it as a documented, opt-in Compose/deployment
pattern when a deployment needs full packet capture; the collector-side bounds
and provenance already hold. It must never grant a decoy `CAP_NET_RAW` or add an
outbound path to a sensor.

## Consequences

- The Cycle C fingerprint/capture items stay unchecked and are tracked by this
  ADR with a clear unblock path for each (paramiko API / licence review /
  privileged capture sidecar).
- No unverified fingerprinting or capture code is shipped, and no sensor gains
  new capability or egress.

## Notes

See ADR 0001–0004 for the ADR convention. ADRs live under `docs/adr/NNNN-title.md`.
