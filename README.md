<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-F2C94C?style=flat-square" alt="Active">
  <img src="https://img.shields.io/badge/category-CYBERSECURITY-22D3EE?style=flat-square" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/stack-Python%20%2B%20Flask-8B949E?style=flat-square" alt="Python and Flask">
  <img src="https://img.shields.io/badge/languages-EN%20%7C%20IT-8B5CF6?style=flat-square" alt="English and Italian">
  <img src="https://img.shields.io/badge/licence-MIT-2EA043?style=flat-square" alt="MIT">
</p>

> Honeypot telemetry, SOC investigation, threat research and cybersecurity study in one evidence-first platform.

<p align="center"><a href="SECURITY.md">Security</a> · <a href="docs/THREAT_MODEL.md">Threat model</a> · <a href="docs/PRIVACY.md">Privacy & retention</a> · <a href="docs/INVESTIGATION.md">Investigation workflow</a> · <a href="LICENSE">MIT Licence</a></p>

---

## What AEGIS-NEXUS is

AEGIS-NEXUS is being built as a **Honeypot + SOC Analysis + Threat Research + Cybersecurity Learning Lab**. Its core rule is to keep raw observations, external enrichment, derived analysis and hypotheses separate.

The current implementation provides both the secure telemetry/investigation foundation and isolated low/intermediate-interaction SSH, web, FTP and Telnet decoys. Captured commands and payloads are emulated or recorded only; they are never executed.

## Implemented now

- Isolated SSH, web, FTP and Telnet decoys plus a Flask collector with bounded JSON ingestion and fail-closed authentication; the standard Compose deployment uses distinct allowlisted keys per built-in sensor.
- Normalized event schema with separate `observed`, `enrichment`, `derived` and `hypotheses` classes.
- External enrichment requires provenance through `source` and `observed_at`.
- Offline local GeoIP/ASN enrichment from operator-supplied MaxMind MMDB files; public source IPs are enriched at the collector without sending captured IPs to a third-party API.
- MITRE ATT&CK and CVE derived mappings are accepted only when they include both `rationale` and `evidence`.
- Deterministic static artifact extraction from observed commands/payloads for URLs, domains, IP literals and common hash formats; extracted values remain evidence-backed derived artifacts, not automatic maliciousness claims.
- Passwords are redacted by default while retaining a SHA-256 fingerprint and length; raw storage is explicit opt-in only.
- Persistent SQLite session correlation that prefers explicit decoy connection IDs or Suricata flow identity and falls back to source IP, honeypot, service, protocol, destination port and inactivity window when needed.
- Investigation APIs and dedicated SOC views for events, IP profiles, sessions, timelines, relationship graphs, Threat Intelligence context and Study Mode.
- Stable cursor pagination for historical event/session navigation; the live dashboard stays on current data while Investigation can append older matching telemetry.
- Evidence-preserving SOC case management with analyst classification, notes, tags, event/session references, audit trail and JSON/CSV case reports.
- SOC dashboard with global search/filters, attacks over time, unique IPs, countries, ASN, ports, protocols, services, honeypots, credentials, commands, IDS alerts, MITRE mappings, temporal heatmap, interactive Attack Map and Live Feed.
- IT/EN interface through a central i18n dictionary; telemetry is rendered as text rather than attacker-controlled HTML.
- Continuous time-based retention with `AEGIS_RETENTION_DAYS` plus the storage ceiling `AEGIS_MAX_DB_EVENTS`; JSON/CSV investigation exports never include cleartext passwords.
- Hardened Docker runtime: non-root user, dropped capabilities, read-only root filesystem, `no-new-privileges`, bounded concurrent TCP connections, per-sensor management networks and localhost-only operator port.
- Sensor containers with CPU/memory/PID/file-descriptor limits and separate exposure/management networks so SSH, web and legacy sensors do not share a lateral management segment.
- Native evidence-first Suricata EVE JSON ingestion for IDS telemetry; alert signatures are preserved as observed IDS output without inventing MITRE or CVE mappings.
- CI for Python tests and Docker image build.

## Data contract

Every event preserves the four provenance classes as distinct sections. No CVE, threat actor, malware family or MITRE technique is invented automatically: insufficient evidence means an empty field.

```json
{
  "honeypot": "ssh-01",
  "event_type": "command",
  "severity": "medium",
  "observed": {
    "source_ip": "203.0.113.10",
    "service": "ssh",
    "protocol": "tcp",
    "destination_port": 22,
    "command": "uname -a"
  },
  "enrichment": {
    "geo": {
      "source": "provider-name",
      "observed_at": "2026-09-22T18:00:00Z",
      "data": {"country": "IT", "latitude": 41.9, "longitude": 12.5}
    }
  },
  "derived": {
    "mitre": [{
      "technique_id": "T1059",
      "rationale": "Command interpreter activity was directly observed",
      "evidence": ["observed.command"]
    }]
  },
  "hypotheses": []
}
```

## Suricata ingestion

Send one Suricata EVE JSON event to `POST /api/v1/integrations/suricata/eve` using `X-Aegis-Key` and `X-Aegis-Sensor`. Alert events become `ids.alert`; AEGIS preserves the Suricata signature and network facts as observed data and leaves `derived` empty unless evidence-backed analysis is added separately.

## Investigation flow

`Dashboard → event → IP → session → timeline → credentials/commands/payload → Threat Intelligence/enrichment → MITRE/CVE/IOC → relations → case → report → Study Mode`

The relationship graph is generated only from data actually present in the selected session. Threat Intelligence displays only stored external enrichment with source/timestamp provenance. Study Mode covers both the selected event and the complete correlated session while keeping analytical limitations visible. See [Investigation workflow](docs/INVESTIGATION.md).

## Quick start

Requires Python 3.12+ or Docker Compose.

```bash
cp .env.example .env
# Replace the SSH, web, legacy and operator placeholder secrets with independent random values.
# Set AEGIS_SURICATA_SENSOR_API_KEY only when Suricata ingestion is used.
docker compose up -d --build
# Dashboard: http://127.0.0.1:8600
```

Development:

```bash
python -m pip install -e '.[dev]'
pytest -q
AEGIS_DATABASE_PATH=./data/aegis.db flask --app aegis_nexus.app run --host 127.0.0.1 --port 8600
```

## Repository structure

```text
src/aegis_nexus/
├── app.py          Flask API, security headers and routes
├── model.py        hostile-input normalization and provenance validation
├── correlation.py session correlation rules
├── enrichment.py  offline local GeoIP/ASN enrichment
├── derivation.py  bounded static observed-artifact extraction
├── casework.py     bounded analyst-case validation
├── backup.py       reusable SQLite backup logic
├── store.py        persistence, analytics, cases, relations and reports
├── study.py        deterministic IT/EN Study Mode
├── sensors/        SSH, web, FTP/Telnet decoys and telemetry client
├── templates/      SOC console
└── static/         i18n, charts, map, live feed and investigation
docs/
├── CASE_MANAGEMENT.md
├── DATA_PROVENANCE.md
├── ENRICHMENT.md
├── INVESTIGATION.md
├── PRIVACY.md
├── SENSOR_ISOLATION.md
└── THREAT_MODEL.md
tests/
```

## Privacy and attribution limits

Honeypot telemetry may contain IP addresses, credentials and payloads. Define a lawful purpose and retention period, restrict operator access and avoid publishing raw sensitive telemetry. IP geolocation, ASN ownership and Threat Intelligence reputation may point to VPNs, proxies, hosting infrastructure, NAT gateways or compromised systems and do not establish the identity of the human behind the activity.

See [Privacy & retention](docs/PRIVACY.md), [Local enrichment](docs/ENRICHMENT.md), the [Threat model](docs/THREAT_MODEL.md) and [Sensor isolation](docs/SENSOR_ISOLATION.md).

## Roadmap

Next implementation cycles focus on additional controlled threat-context adapters, richer investigation exports and additional sensor/IDS integrations. Capabilities are documented when they are implemented, not ahead of the code.

## Licence & responsible use

Released under the [MIT License](LICENSE). Use only on infrastructure you own or are explicitly authorized to monitor. Do not use AEGIS-NEXUS to counter-attack, access third-party systems or publish captured credentials/personal data.

---

© Chiara Berti — 2026
