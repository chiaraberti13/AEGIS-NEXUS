# ADR 0004 — Optional Zeek log ingestion

- Status: **Accepted** (evaluation outcome — feasible, implement on demand)
- Date: 2026-11-24
- Context: ROADMAP Cycle C, "Evaluate optional Zeek log ingestion (`conn`,
  `http`, `ssh`, `dns`) with the same provenance model as Suricata _(evaluate)_"

## Context

Zeek emits structured network logs (`conn.log`, `http.log`, `ssh.log`,
`dns.log`, …). The item asks whether AEGIS should ingest them, with the same
evidence-first provenance model it already uses for Suricata EVE JSON
(`src/aegis_nexus/suricata.py` + the `/api/v1/integrations/suricata/eve`
ingest).

The existing Suricata path is the template: an authenticated, bounded,
hostile-input-safe normalizer maps IDS fields into `observed` /
`observed.network` with explicit `source` + `observed_at` provenance, never
inventing MITRE/CVE or attribution. Zeek ingestion would be structurally
identical — a `zeek.py` normalizer per log type feeding the same event model.

## Decision

**Zeek ingestion is feasible and architecturally aligned; implement it on
demand rather than pre-emptively.** No current deployment requires Zeek
alongside the built-in sensors and the Suricata path. When a deployment needs
it, implement it following the Suricata pattern:

- a `zeek.py` normalizer with one mapping per supported log (`conn`, `http`,
  `ssh`, `dns`) into `observed`/`observed.network`, bounded via the same
  `MAX_*`/normalization machinery as `model.py`;
- a dedicated ingest route authenticated and rate-limited like the Suricata
  route, with a Zeek `source` provenance tag and `observed_at`;
- strictly observed evidence: no attribution, no invented TI/MITRE/CVE; lossy
  normalization disclosed under `collector.normalization`;
- hostile-input and isolation tests mirroring `tests/test_sensors.py` /
  Suricata tests, plus field-mapping tests per log type;
- docs in `docs/NETWORK_EVIDENCE.md` and a threat-model note for the new
  ingest data flow.

Until then the item stays unchecked, tracked by this ADR.

## Consequences

- No new dependency or attack surface is added now; the Suricata ingest remains
  the supported IDS path.
- A future Zeek implementation reuses the Suricata contract, so it adds network
  visibility without changing investigation semantics or the evidence model.

## Notes

See ADR 0001–0003 for the ADR convention. ADRs live under
`docs/adr/NNNN-title.md`.
