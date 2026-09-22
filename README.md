<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-F2C94C?style=flat-square" alt="Active">
  <img src="https://img.shields.io/badge/category-CYBERSECURITY-22D3EE?style=flat-square" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/stack-Python%20%2B%20Flask-8B949E?style=flat-square" alt="Python and Flask">
  <img src="https://img.shields.io/badge/languages-EN%20%7C%20IT-8B5CF6?style=flat-square" alt="English and Italian">
  <img src="https://img.shields.io/badge/licence-MIT-2EA043?style=flat-square" alt="MIT">
</p>

> Honeypot telemetry, SOC investigation, threat research and cybersecurity study in one evidence-first platform.

<p align="center"><a href="SECURITY.md">Security</a> · <a href="docs/THREAT_MODEL.md">Threat model</a> · <a href="docs/PRIVACY.md">Privacy & retention</a> · <a href="LICENSE">MIT Licence</a></p>

---

## What AEGIS-NEXUS is

AEGIS-NEXUS is being built as a **Honeypot + SOC Analysis + Threat Research + Cybersecurity Learning Lab**. Its core rule is to keep raw observations, external enrichment, derived analysis and hypotheses separate.

The current implementation provides the real secure telemetry and investigation foundation. Dedicated SSH/web/legacy deception services will be added on top of this contract instead of being presented as complete before their code exists.

## Implemented now

- Flask collector with bounded JSON ingestion and an optional sensor API key.
- Normalized event schema with separate `observed`, `enrichment`, `derived` and `hypotheses` classes.
- External enrichment requires provenance through `source` and `observed_at`.
- MITRE ATT&CK and CVE derived mappings are accepted only when they include both `rationale` and `evidence`.
- Passwords are redacted by default while retaining a SHA-256 fingerprint and length; raw storage is explicit opt-in only.
- Persistent SQLite session correlation by source IP, honeypot, service and inactivity window.
- Investigation APIs for events, IP profiles, sessions, relationship graphs, Study Mode and evidence-preserving JSON reports.
- SOC dashboard with attacks over time, unique IPs, countries, ASN, ports, protocols, services, honeypots, credentials, commands, IDS alerts, MITRE mappings, temporal heatmap, Attack Map and Live Feed.
- IT/EN interface through a central i18n dictionary; telemetry is rendered as text rather than attacker-controlled HTML.
- Configurable retention with `AEGIS_RETENTION_DAYS`.
- Hardened Docker runtime: non-root user, dropped capabilities, read-only root filesystem, `no-new-privileges`, private management network and localhost-only operator port.
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

## Investigation flow

`Dashboard → event → IP → session → timeline → credentials/commands/payload → enrichment → MITRE/IOC → relations → report`

The relationship graph is generated only from data actually present in the selected session. Study Mode explains why an event is interesting and what a SOC analyst should inspect next while keeping analytical limitations visible.

## Quick start

Requires Python 3.12+ or Docker Compose.

```bash
cp .env.example .env
# Replace AEGIS_INGEST_API_KEY with a long random value.
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
├── store.py        persistence, analytics, relations and reports
├── study.py        deterministic IT/EN Study Mode
├── templates/      SOC console
└── static/         i18n, charts, map, live feed and investigation
docs/
├── DATA_PROVENANCE.md
├── PRIVACY.md
└── THREAT_MODEL.md
tests/
```

## Privacy and attribution limits

Honeypot telemetry may contain IP addresses, credentials and payloads. Define a lawful purpose and retention period, restrict operator access and avoid publishing raw sensitive telemetry. IP geolocation, ASN ownership and Threat Intelligence reputation may point to VPNs, proxies, hosting infrastructure, NAT gateways or compromised systems and do not establish the identity of the human behind the activity.

See [Privacy & retention](docs/PRIVACY.md) and the [Threat model](docs/THREAT_MODEL.md).

## Roadmap

Next implementation cycles focus on isolated honeypot services, signed sensor identity, controlled enrichment adapters, Suricata ingestion, case management, export formats and additional SOC/Study workflows. Capabilities are documented when they are implemented, not ahead of the code.

## Licence & responsible use

Released under the [MIT License](LICENSE). Use only on infrastructure you own or are explicitly authorized to monitor. Do not use AEGIS-NEXUS to counter-attack, access third-party systems or publish captured credentials/personal data.

---

© Chiara Berti — 2026
