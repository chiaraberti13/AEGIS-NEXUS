# ADR 0005 — Cycle C remaining items: client fingerprints and dedicated PCAP capture

- Status: **Accepted** (decisions recorded; items implemented on demand / when unblocked)
- Date: 2026-11-24 · **Updated 2026-11-26** — JA4+ licence evaluation completed
  (JA4/TLS permitted under BSD-3; JA4H and other FoxIO-License-1.1 methods
  declined as native features, GPLv3-incompatible + patent-pending)
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

### HTTP (JA4H) and TLS (JA4) fingerprints — licence evaluation (2026-11-26)

The earlier "blocked pending licence review" is now resolved into a concrete
decision. This is an engineering/licensing analysis, **not formal legal advice**;
final sign-off is the maintainer's. Sources are FoxIO's own LICENSE and License
FAQ in the upstream repository:

- JA4+ overview / FAQ: <https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md>
- FoxIO License 1.1: <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>
- JA4 (TLS) BSD licence: <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4>

**Key fact — AEGIS-NEXUS is licensed GPLv3** (`LICENSE`). Licence *inbound*
compatibility, not only FoxIO's own terms, is therefore decisive.

**The JA4+ suite is split across two licences.**

1. **JA4 — TLS client fingerprint — BSD 3-Clause.** FoxIO's FAQ states JA4
   (TLS Client Fingerprinting) is open-source, BSD 3-Clause (its own
   `LICENSE-JA4`), like JA3. BSD 3-Clause is **GPLv3-compatible**, so a native
   JA4 implementation may be incorporated into this GPLv3 project, keeping the
   BSD copyright/attribution notice for that component. Caveat: BSD 3-Clause
   carries **no express patent grant** and FoxIO's FAQ says "all JA4+ methods …
   are patent pending"; for a defensive, non-commercial honeypot the practical
   risk is low, and FoxIO released JA4 under BSD precisely to drive adoption, but
   the maintainer should accept that residual risk knowingly.

2. **JA4H, JA4S, JA4SSH, JA4X, JA4T, JA4L and all other suite members —
   FoxIO License 1.1.** This licence grants a copyright licence to use and modify
   the software **"only for non-commercial purposes"**, and explicitly treats as
   *commercial* (i.e. excluded) "any use for which you charge fees or anything
   else of value", providing it "on a hosted or managed service basis", and
   providing "maintenance, support or development services … to others".
   Internal business use is allowed only "in a manner where you do not directly
   monetize the software"; selling it in a product needs a separate **OEM
   licence** from FoxIO. In substance this is a **non-commercial-only** licence
   (the PolyForm-Noncommercial pattern).

**Decision for the FoxIO-License-1.1 methods (JA4H included): decline native
implementation; do not vendor or reimplement FoxIO JA4+ code into this
repository.** Two independent reasons, either sufficient:

- **Licence incompatibility.** A non-commercial-only, field-of-use-restricted
  licence cannot be combined into a GPLv3 work: GPLv3 forbids adding downstream
  restrictions (§7, §10) and requires the freedom to run the program for any
  purpose. The conflict exists **regardless of how AEGIS-NEXUS itself is used** —
  it is about what terms the *distributed combined work* can carry, which GPLv3
  fixes as GPLv3 and FoxIO 1.1 forbids. Dual-licensing the sensor code would not
  cure a GPLv3 derivative that embeds the restricted method.
- **Patent-pending status.** FoxIO states the methods and their detection logic
  are patent pending, so a clean-room reimplementation "from the published spec"
  — which would side-step *copyright* — does **not** side-step the patent. The
  usual copyright escape hatch therefore does not apply here.

**Supported path instead (no FoxIO code, no licence conflict):** ingest
fingerprint *values* computed by an external producer the operator already runs
— **Suricata** (JA3/JA3S/JA4 passthrough already implemented) or Zeek (ADR
0004) — and store them as `observed`/`observed.network` evidence. Consuming a
fingerprint *string* emitted by a separately-licensed tool is not redistributing
FoxIO's implementation and does not embed the method in AEGIS-NEXUS; the value
stays a **tooling hint, never identity**, with provenance and bounded
hostile-input handling. This keeps JA4-family HTTP/SSH/TLS signals available to
operators who want them, via a component they chose to deploy, without taking the
FoxIO licence or patent exposure into the GPLv3 codebase.

**Net effect on the ROADMAP items:**
- "sensor-native JA4 TLS fingerprints" — **permitted** (BSD-3), implementable on
  demand if a decoy is extended to capture the TLS ClientHello; low priority
  while Suricata passthrough covers it.
- "HTTP client fingerprints (JA4H)" and HASSH-via-JA4SSH — **declined** as a
  native AEGIS feature under the current GPLv3 + FoxIO-1.1 + patent situation;
  delivered only through external-producer ingestion. Revisit only if FoxIO
  re-licenses these methods under a GPL-compatible, patent-granting licence, or
  the maintainer obtains an OEM licence *and* resolves the GPLv3 relicensing.

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

- The JA4+ licence question is **decided**, not merely flagged: JA4/TLS is
  permitted (BSD-3) and implementable on demand; JA4H and the other
  FoxIO-License-1.1 methods are **declined** as native AEGIS-NEXUS features
  (GPLv3-incompatible non-commercial licence + patent-pending methods) and are
  supported only via external-producer (Suricata/Zeek) value ingestion.
- The HASSH item (KEX/cipher offers) remains deferred on the paramiko-private-API
  ground above; a JA4SSH-based route is additionally subject to the same FoxIO
  1.1 decline.
- Dedicated-container PCAP capture remains documented opt-in deployment
  infrastructure (below).
- No unverified fingerprinting or capture code is shipped, no FoxIO-licensed code
  enters the GPLv3 repository, and no sensor gains new capability or egress.

## Notes

See ADR 0001–0004 for the ADR convention. ADRs live under `docs/adr/NNNN-title.md`.
