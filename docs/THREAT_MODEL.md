# Threat model / Modello di minaccia

Primary trust assumption: every byte arriving from a honeypot or network sensor is hostile.

Key threats and controls:
- XSS/log injection -> JSON-only ingestion, bounded normalization, text-only rendering, strict CSP.
- Resource exhaustion -> request-size limits, list/depth/string bounds, API query limits.
- Credential leakage -> redaction by default, optional explicit raw-secret mode.
- Collector compromise -> non-root container, read-only root filesystem, dropped capabilities, `no-new-privileges`, management-only Docker network.
- Pivoting -> analytics network is `internal: true`; future trap containers must use a distinct DMZ and no unnecessary egress.
- False analytical certainty -> provenance separation; MITRE/CVE derived mappings require evidence and rationale; hypotheses remain separate.
- Attribution errors -> IP/geo/ASN/reputation are treated as context only.

Remaining work before Internet exposure: authenticated operator access, reverse-proxy TLS, edge rate limiting, backup/retention automation, signed sensor identity and dedicated honeypot services in an isolated DMZ.
