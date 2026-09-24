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

### Built-in rules

Single-event rules:

- `download_attempt` — a captured command contains a known download utility/primitive.
- `command_staging_detected` — a captured command contains a decoding/execution staging primitive.
- `suricata_high_severity` — observed Suricata telemetry reports severity 1 or 2.

Temporal rules use a bounded evidence window anchored to the event timestamp, so historical imports are evaluated consistently:

- `multiple_auth_failures` — at least 5 credential attempts from one source within 5 minutes.
- `credential_bruteforce` — at least 10 credential attempts covering at least 5 usernames from one source within 10 minutes.
- `credential_reuse` — the same credential-secret SHA-256 fingerprint is observed from at least 2 source IPs within 24 hours. Raw passwords are not queried by this rule and reuse is not actor attribution.
- `web_scanning` — at least 8 distinct HTTP paths from one source within 5 minutes. The web decoy records bounded metadata for unknown/404 paths so this behavior is observable.
- `path_traversal_sequence` — at least 3 path-traversal-bearing requests/payloads from one source within 5 minutes.
- `rapid_port_sequence` — at least 5 distinct destination ports from one source within 2 minutes.
- `recon_burst` — at least 15 events from one source within 5 minutes with multi-service or multi-port breadth.

Thresholds are intentionally explicit and deterministic. They are detection conditions, not statements about attacker identity or intent. These rules do not automatically create MITRE ATT&CK, CVE or threat-actor mappings.

### Investigation relationships

Alert detail exposes the retained event references, related session IDs and IOC already derived from those events. IOC remain `derived` evidence and are not promoted to threat intelligence. An alert can be referenced by an investigation case together with its source events and sessions; the case remains analyst-authored context.

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

### Regole integrate

Regole su singolo evento:

- `download_attempt` — un comando catturato contiene una utility/primitiva nota per il download.
- `command_staging_detected` — un comando catturato contiene una primitiva di decoding/esecuzione compatibile con staging.
- `suricata_high_severity` — la telemetria Suricata osservata riporta severity 1 o 2.

Le regole temporali usano una finestra di evidenze limitata e ancorata al timestamp dell'evento, quindi funzionano in modo coerente anche sugli import storici:

- `multiple_auth_failures` — almeno 5 tentativi di credenziali dalla stessa sorgente in 5 minuti.
- `credential_bruteforce` — almeno 10 tentativi su almeno 5 username dalla stessa sorgente in 10 minuti.
- `credential_reuse` — lo stesso fingerprint SHA-256 del secret viene osservato da almeno 2 IP sorgente in 24 ore. La regola non interroga password in chiaro e il riuso non equivale ad attribuzione.
- `web_scanning` — almeno 8 path HTTP distinti dalla stessa sorgente in 5 minuti. Il web decoy registra metadati limitati anche per path sconosciuti/404.
- `path_traversal_sequence` — almeno 3 richieste/payload con evidenza di path traversal dalla stessa sorgente in 5 minuti.
- `rapid_port_sequence` — almeno 5 porte di destinazione distinte dalla stessa sorgente in 2 minuti.
- `recon_burst` — almeno 15 eventi dalla stessa sorgente in 5 minuti con ampiezza multi-servizio o multi-porta.

Le soglie sono esplicite e deterministiche. Sono condizioni di detection, non affermazioni sull'identità o sull'intento dell'attaccante. Le regole non generano automaticamente mapping MITRE ATT&CK, CVE o attribuzioni a threat actor.

### Relazioni investigative

Il dettaglio alert espone i riferimenti agli eventi conservati, le sessioni correlate e gli IOC già derivati da tali eventi. Gli IOC restano evidenza `derived` e non vengono promossi a Threat Intelligence. Un alert può essere referenziato da un case insieme agli eventi e alle sessioni sorgente; il case resta contesto creato dall'analista.
