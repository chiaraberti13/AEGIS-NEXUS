# ADR 0005 — Cycle C remaining items: client fingerprints and dedicated PCAP capture

- Status: **Accepted** (decisions recorded; items implemented on demand / when unblocked)
- Date: 2026-11-24 · **Updated 2026-11-26** — (1) SSH KEXINIT offer lists +
  native HASSH (Salesforce, BSD-3) implemented; (2) JA4+ licence evaluation
  completed (JA4/TLS permitted under BSD-3; JA4H and other FoxIO-License-1.1
  methods declined as native features, GPLv3-incompatible + patent-pending);
  (3) dedicated-container PCAP capture provided as an opt-in Compose overlay
- Context: the remaining open Cycle C ("Network Evidence & Visibility") items:
  SSH client version + KEX/cipher offers and HASSH fingerprints; HTTP (JA4H)
  and TLS (JA4) fingerprints; and dedicated-container PCAP capture (BPF,
  ring-buffer).

## Decision

Each remaining item is decided here so none is left dangling. None is shipped
unverified or over a boundary the project forbids.

### SSH client version + KEX/cipher offers, HASSH — implemented (2026-11-26)

The SSH client **version string** was already captured
(`paramiko.Transport.remote_version` → `observed.network.ssh.client_version`).
The client **KEX/cipher/MAC/compression offer lists** and the **HASSH**
fingerprint are now captured too.

paramiko does not expose the peer's offer lists through a public API, but it does
keep the peer's raw `SSH_MSG_KEXINIT` bytes in `remote_kex_init` while parsing
them (it clears the field once the key exchange completes, so it is gone by the
time `start_server` returns). `CapturingSSHTransport` overrides the private
`_parse_kex_init` to call the real parser and snapshot that buffer; the decoy
then parses the snapshot with the **public** `paramiko.Message` API. This touches
exactly one private name, and does so fail-safe: if a future paramiko renames or
drops `_parse_kex_init`/`remote_kex_init`, the override simply does not run, the
snapshot stays unset, HASSH is skipped, and the decoy keeps working — no crash,
never a wrong fingerprint.

HASSH follows the Salesforce definition `md5(kex;enc_c2s;mac_c2s;comp_c2s)` over
the client offer lists. **Salesforce HASSH is BSD-3-Clause** (not part of the
FoxIO JA4+ suite), so it is GPLv3-compatible — unlike JA4SSH, which is a
FoxIO-License-1.1 method and stays declined per the evaluation below. The offer
lists and digest are recorded as `observed.network.ssh` (`kex_algorithms`,
`server_host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`,
`compression_algorithms`, `hassh`, `hassh_algorithms`) — a **tooling hint, never
identity**. The lists are attacker-influenced, so each is bounded (≤128
algorithms × ≤64 chars) and `validate_network_evidence` re-enforces those caps on
the collector side (fail-closed); when the lists exceed the caps they are
truncated (disclosed under `sensor_capture`) and HASSH is omitted, since a digest
over truncated lists would match no real client. Guarded by `tests/test_sensors.py`
(capture, bounding, fail-safe, HASSH vector) and collector-side validation tests
in `tests/test_network_evidence.py`.

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

**Net effect on the ROADMAP items (both now closed by decision):**
- "sensor-native JA4 TLS fingerprints" — licence-**permitted** (BSD-3,
  GPLv3-compatible), but the team **declines to build it now**. Suricata's
  JA3/JA3S/JA4 passthrough already supplies JA4 as observed evidence, and a
  native implementation would mean standing up a TLS-terminating decoy that reads
  the ClientHello — non-trivial new handshake attack surface and ongoing
  maintenance for marginal analytic gain over the existing passthrough. **Reopen
  trigger:** a deployment that needs JA4 without running Suricata/Zeek.
- "HTTP client fingerprints (JA4H)" and HASSH-via-JA4SSH — **declined** as a
  native AEGIS feature under the current GPLv3 + FoxIO-1.1 + patent situation;
  delivered only through external-producer ingestion. **Reopen trigger:** FoxIO
  re-licenses these methods under a GPL-compatible, patent-granting licence, or
  the maintainer obtains an OEM licence *and* resolves the GPLv3 relicensing.

Native **HASSH** (Salesforce, BSD-3) is the one SSH-family fingerprint AEGIS
computes itself, precisely because its licence is GPLv3-compatible; the FoxIO
JA4+ methods are not, which is the whole reason for the split above.

### Dedicated-container PCAP capture (BPF, ring-buffer) — deployment infrastructure

Bounded PCAP capture already exists in-app (size/retention limits, SHA-256,
session association, authenticated+audited attachment download — ADR-adjacent,
done). The dedicated-container capture is now **provided as an opt-in Compose
overlay** (`docker-compose.pcap.yml` + `docker/pcap/`, docs in
`docs/PCAP_CAPTURE.md`): one `tcpdump` sidecar per decoy that **shares the
decoy's network namespace** (`network_mode: "service:<decoy>"`) so it sees only
that decoy's own traffic (non-promiscuous, BPF-filtered to the decoy's ports),
holds **`CAP_NET_RAW` in the sidecar while the decoy keeps `cap_drop: ALL`**,
runs read-only + `no-new-privileges`, drops to `nobody` after opening the socket,
and writes a bounded ring buffer (hard disk cap) to a dedicated volume. The
isolation invariants are machine-checked by `scripts/verify_compose_isolation.py`
(each `*-pcap` sidecar adds exactly `CAP_NET_RAW` and nothing else, shares a
decoy netns, owns no network/ports; no decoy carries any `cap_add`), wired into
CI alongside the Compose-config validation and the image build.

This is deployment infrastructure: **live capture cannot be exercised in the
project's unit-test environment**, so CI validates config, isolation and image
build but does not prove packets are captured — that is verified in a real
deployment. The pattern never grants a decoy `CAP_NET_RAW`; the only network path
a sidecar has is the decoy's own (an exposure net + an `internal` management
net), and the capture process opens no outbound connections — hard egress
guarantees remain the operator's host/VLAN perimeter control, as for the decoys
themselves.

## Consequences

- The JA4+ licence question is **decided**, not merely flagged: JA4/TLS is
  permitted (BSD-3) and implementable on demand; JA4H and the other
  FoxIO-License-1.1 methods are **declined** as native AEGIS-NEXUS features
  (GPLv3-incompatible non-commercial licence + patent-pending methods) and are
  supported only via external-producer (Suricata/Zeek) value ingestion.
- The HASSH item (KEX/cipher offer lists + HASSH) is **implemented** natively
  (Salesforce HASSH, BSD-3), via a fail-safe snapshot of paramiko's
  `remote_kex_init`. A JA4SSH-based route stays declined under the FoxIO 1.1
  evaluation above; HASSH does not need it.
- Dedicated-container PCAP capture is **provided** as an opt-in Compose overlay
  (`docker-compose.pcap.yml`, `docker/pcap/`, `docs/PCAP_CAPTURE.md`), with the
  capture capability isolated in per-decoy sidecars and the isolation invariants
  CI-checked. Live capture stays a deployment-verified concern, not a unit test.
- No unverified fingerprinting code is shipped, no FoxIO-licensed code enters the
  GPLv3 repository, and **no decoy gains `CAP_NET_RAW` or a new egress path** —
  the capture capability lives only in the opt-in sidecar's own container.

## Notes

See ADR 0001–0004 for the ADR convention. ADRs live under `docs/adr/NNNN-title.md`.
