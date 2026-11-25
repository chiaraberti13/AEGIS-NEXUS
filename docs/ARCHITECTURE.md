# Internal architecture / Architettura interna

## English

AEGIS-NEXUS is a single-node collector that ingests authenticated sensor
telemetry, stores it evidence-first, derives analysis, and serves a SOC console
and APIs. This page is the map of the code; invariants live in `CONTRIBUTING.md`
and the conventions skill.

### Components

- **Sensors** (`src/aegis_nexus/sensors/`): decoys (SSH, web, FTP/Telnet, SMTP,
  Redis, MySQL, SMB, generic TCP) behind a plugin contract (`base.py`,
  `registry.py`). They emulate only, never execute attacker input, and post
  signed telemetry via `SensorClient`. Sensors run isolated and gain no
  outbound path except posting to the collector.
- **Collector app** (`app.py`): the Flask `create_app` factory. All config is
  `AEGIS_*` env read in one place. A `before_request` trust boundary makes every
  `/api/v1/*` operator route fail closed, and sensor ingest is separately
  authenticated (key, optional HMAC signature + anti-replay nonce). Routes are
  being split out of the factory by domain via the blueprint-factory pattern
  (ADR 0003): a module-level `make_<domain>_blueprint(...)` captures its
  dependencies and returns a Flask `Blueprint` with the same absolute URLs, so
  the app-level request hooks still apply and behaviour is unchanged. First
  domain extracted: `api_detections.py` (`/api/v1/detections/*`).
- **Model** (`model.py`): `normalize_event` — bounded, hostile-input-safe
  normalization into the four provenance classes; disclosed, never silent, loss.
- **Derivation & enrichment** (`derivation.py`, `enrichment.py`,
  `threat_context.py`, `benign_scanners.py`): deterministic IOC extraction and
  offline GeoIP/ASN + local threat context — all `derived`/`enrichment`, never
  attribution.
- **Detection** (`detection.py`, `detection_config.py`, `detection_coverage.py`,
  `detection_backtest.py`, `alerts.py`): evidence-backed rules → alerts; ATT&CK
  coverage and backtesting are read-only views.
- **Storage** (`store.py`): raw SQLite (WAL) behind the `StorageBackend`
  interface (`storage_backend.py`); forward-only migrations (`migrations.py`)
  keyed on `PRAGMA user_version`; tamper-evident event hash chain
  (`event_chain.py`); backups + restore verification (`backup.py`). The
  storage domains are extracted into focused modules — relationship-graph
  projection (`store_relations.py`), case management (`store_cases.py`), analytics
  /dashboard (`store_analytics.py`), event reads (`store_events.py`) and session
  reads (`store_sessions.py`), the last four as mixins that `Store` composes,
  with shared vocabulary in the dependency-free `store_common.py` — as
  incremental Cycle I storage splits (ADR 0003); `Store` keeps the write/ingest
  core (ingest, migrations hooks, retention, health, counters, IP/threat
  profiles) and remains the composed reference backend with unchanged public
  behaviour.
- **Cases & reporting** (`casework.py`, `reporting.py`, `evidence_bundle.py`,
  `redaction.py`, `pdf.py`, `soc_summary.py`): analyst workspaces and
  JSON/CSV/Markdown/PDF exports with redaction profiles and a SHA-256 evidence
  bundle.
- **Operations** (`metrics.py`, `logging_config.py`, forwarding in
  `forwarding.py`): platform health, Prometheus metrics, JSON logging and
  collector-only SIEM forwarding.
- **Frontend** (`static/app.js`, `static/i18n.js`, `templates/index.html`):
  a single vanilla-JS IIFE, no build step, bilingual, safe DOM only.

### Ingest flow

`POST /api/v1/events` → content-type/size guard → sensor auth (key/signature/
nonce) → rate limit → load-shed if disk-critical → `normalize_event` → clock
validation → `derive_observed_artifacts` → GeoIP/threat-context/benign-scanner
enrichment → `store.ingest` → detection (`record_detection_findings`) → optional
SIEM forward. Each rejection is counted; evidence loss is always disclosed.

### Ports & adapters

The `StorageBackend` protocol is the main port; `Store` (SQLite) is the
reference adapter. A PostgreSQL adapter is deferred (ADR 0002). Enrichment,
threat-context and passive-fingerprint providers are pluggable interfaces so
external context can be swapped without touching the evidence model.

### Type checking

A mypy gate (`pyproject.toml [tool.mypy]`, `make typecheck`) covers a curated
set of core modules and expands as modules are annotated.

---

## Italiano

AEGIS-NEXUS è un collector a nodo singolo che ingerisce telemetria autenticata
dai sensori, la memorizza evidence-first, deriva analisi e serve una console SOC
e delle API. Questa pagina è la mappa del codice; gli invarianti stanno in
`CONTRIBUTING.md` e nella skill delle convenzioni.

### Componenti

- **Sensori** (`src/aegis_nexus/sensors/`): decoy (SSH, web, FTP/Telnet, SMTP,
  Redis, MySQL, SMB, TCP generico) dietro un contratto a plugin (`base.py`,
  `registry.py`). Emulano soltanto, non eseguono mai l'input dell'attaccante, e
  inviano telemetria firmata via `SensorClient`. Girano isolati e non
  acquisiscono percorsi in uscita se non il post verso il collector.
- **App collector** (`app.py`): la factory Flask `create_app`. Tutta la config è
  da env `AEGIS_*` letta in un unico punto. Un trust boundary `before_request`
  rende fail-closed ogni rotta operatore `/api/v1/*`; l'ingest sensori è
  autenticato a parte (chiave, HMAC opzionale + nonce anti-replay). Le rotte
  vengono estratte dalla factory per dominio con il pattern blueprint-factory
  (ADR 0003): una `make_<dominio>_blueprint(...)` a livello di modulo cattura le
  sue dipendenze e restituisce un `Blueprint` Flask con gli stessi URL
  assoluti, così gli hook di request a livello app continuano ad applicarsi e il
  comportamento resta invariato. Primo dominio estratto: `api_detections.py`
  (`/api/v1/detections/*`).
- **Model** (`model.py`): `normalize_event` — normalizzazione bounded e sicura
  su input ostile nelle quattro classi di provenance; perdita dichiarata, mai
  silenziosa.
- **Derivazione & enrichment** (`derivation.py`, `enrichment.py`,
  `threat_context.py`, `benign_scanners.py`): estrazione IOC deterministica e
  GeoIP/ASN offline + threat context locale — tutto `derived`/`enrichment`, mai
  attribuzione.
- **Detection** (`detection.py`, `detection_config.py`, `detection_coverage.py`,
  `detection_backtest.py`, `alerts.py`): regole evidence-backed → alert; coverage
  ATT&CK e backtesting sono viste read-only.
- **Storage** (`store.py`): SQLite raw (WAL) dietro l'interfaccia
  `StorageBackend` (`storage_backend.py`); migrazioni forward-only
  (`migrations.py`) su `PRAGMA user_version`; hash-chain degli eventi a prova di
  manomissione (`event_chain.py`); backup + verifica restore (`backup.py`). La
  domini di storage sono estratti in moduli dedicati — proiezione del grafo di
  relazioni (`store_relations.py`), gestione casi (`store_cases.py`), analytics
  /dashboard (`store_analytics.py`), letture eventi (`store_events.py`) e
  letture sessioni (`store_sessions.py`), gli ultimi quattro come mixin che
  `Store` compone, con vocabolario condiviso nel modulo senza dipendenze
  `store_common.py` — come split incrementali del Cycle I (ADR 0003); `Store`
  mantiene il core di scrittura/ingest (ingest, hook migrazioni, retention,
  health, counter, profili IP/threat) e resta il backend di riferimento
  composto, con comportamento pubblico invariato.
- **Casi & reporting** (`casework.py`, `reporting.py`, `evidence_bundle.py`,
  `redaction.py`, `pdf.py`, `soc_summary.py`): workspace dell'analista ed export
  JSON/CSV/Markdown/PDF con profili di redazione e bundle di evidenze con
  manifest SHA-256.
- **Operazioni** (`metrics.py`, `logging_config.py`, forwarding in
  `forwarding.py`): salute della piattaforma, metriche Prometheus, log JSON e
  forwarding SIEM solo-collector.
- **Frontend** (`static/app.js`, `static/i18n.js`, `templates/index.html`): un
  singolo IIFE vanilla-JS, senza build step, bilingue, solo DOM sicuro.

### Flusso di ingest

`POST /api/v1/events` → guardia content-type/dimensione → auth sensore
(chiave/firma/nonce) → rate limit → load-shed se disco critico →
`normalize_event` → validazione clock → `derive_observed_artifacts` →
enrichment GeoIP/threat-context/benign-scanner → `store.ingest` → detection
(`record_detection_findings`) → forwarding SIEM opzionale. Ogni rifiuto è
contato; la perdita di evidenza è sempre dichiarata.

### Porte & adattatori

Il protocollo `StorageBackend` è la porta principale; `Store` (SQLite) è
l'adattatore di riferimento. Un adattatore PostgreSQL è deferito (ADR 0002). I
provider di enrichment, threat-context e fingerprint passivi sono interfacce
sostituibili, così il contesto esterno si può cambiare senza toccare il modello
di evidenza.

### Type checking

Un gate mypy (`pyproject.toml [tool.mypy]`, `make typecheck`) copre un set
curato di moduli core e si espande man mano che i moduli vengono annotati.
