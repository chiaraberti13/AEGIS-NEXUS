# Threat model / Modello di minaccia

Primary trust assumption: every byte arriving from a honeypot or network sensor is hostile.

Key threats and current controls:

- XSS/log injection -> JSON-only ingestion, bounded normalization, text-only rendering and strict CSP.
- Injection/path abuse -> parameterized SQLite queries, bounded identifiers, no attacker-controlled filesystem paths and no payload execution.
- Resource exhaustion -> request-size limits, bounded strings/depth/cardinality, rejection of non-finite numeric telemetry, analytics/session query ceilings with explicit truncation metadata, bounded-cost API rate limiting, container resource limits and bounded concurrent sensor connections.
- Credential leakage -> redaction by default, explicit raw-database opt-in only, and mandatory cleartext suppression from decoded operator APIs, UI and investigation exports.
- Sensor spoofing/replay -> per-sensor/shared secrets, sensor identity binding and optional required HMAC request signatures with bounded timestamp skew.
- Unauthorized SOC access -> independent operator key, fail-closed API behavior when the key is absent, explicit development-only unauthenticated opt-in, session-only browser storage, API authorization and operator rate limiting.
- Collector compromise -> non-root runtime, read-only root filesystem, dropped capabilities, `no-new-privileges`, localhost-only operator exposure.
- Pivoting -> separate exposure and management networks per sensor; sensors do not share a lateral management segment. Host/VLAN firewalling remains required for production isolation and egress control.
- Persistent-storage exhaustion -> time retention, event-count ceiling, WAL checkpointing and backup rotation.
- False analytical certainty -> `observed`, `enrichment`, `derived` and `hypotheses` remain separate; MITRE/CVE mappings require rationale and evidence.
- Threat-feed poisoning/staleness -> local threat context is opt-in, exact-match only, bounded, source/timestamp preserving and never changes severity or attribution automatically; feed trust and update policy remain operator responsibilities.
- Attribution errors -> IP/geolocation/ASN/reputation are contextual only and never become threat-actor attribution automatically.
- Case-management confusion -> case status/severity/notes are explicitly analyst classifications; evidence links reference source telemetry and do not copy it into the case store.
- Evidence loss through retention -> cases preserve identifiers and expose evidence availability; operators must treat unavailable references as missing source telemetry, not as negative evidence.

Internet-facing deployment still requires controls outside the application boundary: dedicated VM/VLAN or host, deny routes to production networks, restrict egress, host/network firewalling, TLS termination, monitoring of the Docker host, key rotation and a documented legal/privacy retention policy. The repository includes a reverse-proxy/rate-limit example, but deployment-specific perimeter controls remain the operator's responsibility.


## Nota aggiuntiva / Additional note

- Impersonificazione tra sensori: il deployment Compose assegna credenziali distinte ai decoy integrati e il collector usa un'allowlist; le identità non configurate vengono rifiutate.
