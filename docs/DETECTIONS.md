# Detection & Alert Semantics / Semantica Detection e Alert

## English

AEGIS-NEXUS detections are deterministic, evidence-backed findings generated from retained telemetry. A detection is **not** attribution and does not identify a human, organization, malware family or campaign unless such context is separately supplied by a provenance-bearing source.

### Versioned rule contract

Every finding records:

- `schema_version`: version of the detection finding contract.
- `rule_id`: stable machine-readable rule identifier.
- `rule_version`: version of the rule logic that produced the finding.
- `severity`: operational importance of the matched behavior.
- `confidence`: confidence that the rule's documented condition matched the stored evidence; it is not confidence in attacker identity or intent.
- `evidence`: references to the retained events supporting the alert.
- `source_ip` and `session_id`: investigation pivots when available.

Alerts are stored separately from source events. Detection processing never rewrites observed telemetry, enrichment, derived artifacts or analyst hypotheses.

### Alert lifecycle

`new → acknowledged → investigating → closed`

Analyst tags and notes are explicitly analyst-authored context. Closing an alert does not delete its evidence references. A later matching event may create a new alert after the previous alert has been closed.

### Deduplication

Open alerts are aggregated only when rule ID/version, source IP and session ID match. Each matching event remains a distinct evidence reference and increments the occurrence count.

### Initial built-in rules

- `download_attempt` — a captured command contains a known download utility/primitive.
- `command_staging_detected` — a captured command contains a decoding/execution staging primitive.
- `suricata_high_severity` — observed Suricata telemetry reports severity 1 or 2.

These rules describe observable behavior only. They do not automatically create MITRE ATT&CK, CVE or threat-actor mappings.

---

## Italiano

Le detection di AEGIS-NEXUS sono risultati deterministici, supportati da evidenze e generati dalla telemetria conservata. Una detection **non è attribuzione** e non identifica una persona, organizzazione, malware family o campagna, salvo che tale contesto provenga separatamente da una fonte con provenance esplicita.

### Contratto versionato delle regole

Ogni finding registra:

- `schema_version`: versione del contratto del finding.
- `rule_id`: identificatore stabile e machine-readable della regola.
- `rule_version`: versione della logica che ha prodotto il finding.
- `severity`: rilevanza operativa del comportamento osservato.
- `confidence`: confidenza che la condizione documentata dalla regola corrisponda all'evidenza memorizzata; non misura l'identità o l'intento dell'attaccante.
- `evidence`: riferimenti agli eventi conservati che supportano l'alert.
- `source_ip` e `session_id`: pivot investigativi quando disponibili.

Gli alert sono memorizzati separatamente dagli eventi sorgente. Il processing delle detection non riscrive telemetria observed, enrichment, derived artifacts o hypotheses dell'analista.

### Lifecycle degli alert

`new → acknowledged → investigating → closed`

Tag e note sono contesto esplicitamente aggiunto dall'analista. La chiusura di un alert non elimina i riferimenti alle evidenze. Un evento successivo può creare un nuovo alert se quello precedente è già chiuso.

### Deduplicazione

Gli alert aperti vengono aggregati solo quando coincidono rule ID/version, source IP e session ID. Ogni evento resta un riferimento di evidenza distinto e incrementa il contatore delle occorrenze.

### Prime regole integrate

- `download_attempt` — un comando catturato contiene una utility/primitiva nota per il download.
- `command_staging_detected` — un comando catturato contiene una primitiva di decoding/esecuzione compatibile con staging.
- `suricata_high_severity` — la telemetria Suricata osservata riporta severity 1 o 2.

Queste regole descrivono esclusivamente comportamento osservabile. Non generano automaticamente mapping MITRE ATT&CK, CVE o attribuzioni a threat actor.
