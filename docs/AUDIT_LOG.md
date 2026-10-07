# Operator audit log / Registro di audit dell'operatore

## English

AEGIS-NEXUS keeps an **append-only operator audit log** so that analyst actions
against captured evidence are attributable to a named operator (Cycle P
operator identities). It answers *who did what, to which entity, when and from
where* — without duplicating the evidence itself.

### What is recorded

Every successful operator action in these categories is logged:

| Action | Trigger |
|---|---|
| `alert.update` | alert status/tag change (`PATCH /api/v1/alerts/<id>`) |
| `alert.note_add` | note added to an alert |
| `case.create` / `case.update` / `case.delete` | case lifecycle |
| `case.evidence_add` / `case.evidence_remove` | case evidence links |
| `case.note_add` | note added to a case |
| `export.ioc_csv` | IOC CSV export |
| `export.stix` | Threat-context STIX export |
| `export.case_report` | case report download (Markdown/CSV) |
| `export.session_report` | session report download (Markdown/CSV) |
| `pcap.upload` / `pcap.capture` / `pcap.download` | PCAP evidence access |
| `audit.retention_prune` | system entry recording a retention prune as evidence loss |

Each entry stores the UTC timestamp, the authenticated operator identity, the
action, the target type and identifier, the outcome, the request source IP and
a small structured `detail` object (for example the new alert status or the
export format).

### What is deliberately not recorded

The trail stores **attribution and metadata, never content**: operator note
bodies and attacker-controlled payloads are never copied into it (an alert/case
note records only its length or nothing). This keeps the log useful without
turning it into a second, unbounded copy of personal data or hostile input.

### Append-only guarantees

- Rows are **immutable**: a `BEFORE UPDATE` SQLite trigger
  (`operator_audit_log_no_update`) rejects any in-place edit.
- The `id` is a monotonic `AUTOINCREMENT`, so any out-of-band deletion of a
  mid-sequence row is visible as a gap.
- The only deletions are **bounded, oldest-first retention prunes**, which are
  themselves recorded as an `audit.retention_prune` entry (evidence loss is
  explicit, never silent).
- Auditing never breaks the action it records: the request has already
  succeeded, so a logging failure is swallowed and surfaced in the application
  log rather than turned into a 5xx.

This is tamper-evident at the application layer; like the event hash chain it
does **not** defend against an attacker who rewrites the whole database.

### Reading the log

`GET /api/v1/audit` (operator-authenticated) returns the most recent entries,
newest first, with optional `operator`, `action`, `target_type`, `target_id`
and `limit` filters, plus the configured `retention_days` and `max_rows`.

The log is surfaced in two operator-facing places:

- **Dashboard → Audit view.** A dedicated workspace lists the entries in a
  table (timestamp, operator, action, target, outcome, source IP, detail) with
  the same operator/action/target filters and the retention summary. Every
  field is rendered as text, never HTML, so operator-supplied target IDs and
  detail values cannot inject markup.
- **Case reports.** A case JSON, Markdown case report carries an
  `operator_audit` section scoped to that case (`target_type=case`,
  `target_id=<case id>`): who created, changed, linked/removed evidence for,
  annotated or exported the case, attributed to the authenticated operator.
  This complements the case's own history so a report is a complete
  accountability record. (CSV stays a flat evidence table.)

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_AUDIT_LOG_RETENTION_DAYS` | `365` | Age bound; `0` disables age pruning. Intentionally longer than telemetry retention so actions stay attributable. |
| `AEGIS_AUDIT_LOG_MAX_ROWS` | `1000000` | Row ceiling; `0` disables the count bound. |

The operator identity and request source IP are personal data; see
[`PRIVACY.md`](PRIVACY.md) for retention and handling.

---

## Italiano

AEGIS-NEXUS mantiene un **registro di audit dell'operatore in sola aggiunta
(append-only)** affinché le azioni dell'analista sulle evidenze catturate siano
attribuibili a un operatore nominativo (identità operatore del Ciclo P).
Risponde a *chi ha fatto cosa, su quale entità, quando e da dove* — senza
duplicare l'evidenza stessa.

### Cosa viene registrato

Ogni azione operatore riuscita in queste categorie viene registrata:

| Azione | Attivazione |
|---|---|
| `alert.update` | cambio stato/tag di un alert (`PATCH /api/v1/alerts/<id>`) |
| `alert.note_add` | nota aggiunta a un alert |
| `case.create` / `case.update` / `case.delete` | ciclo di vita del caso |
| `case.evidence_add` / `case.evidence_remove` | collegamenti evidenza del caso |
| `case.note_add` | nota aggiunta a un caso |
| `export.ioc_csv` | export CSV degli IOC |
| `export.stix` | export STIX del threat context |
| `export.case_report` | download report del caso (Markdown/CSV) |
| `export.session_report` | download report della sessione (Markdown/CSV) |
| `pcap.upload` / `pcap.capture` / `pcap.download` | accesso all'evidenza PCAP |
| `audit.retention_prune` | voce di sistema che registra una potatura come perdita di evidenza |

Ogni voce memorizza il timestamp UTC, l'identità operatore autenticata,
l'azione, il tipo e l'identificatore del target, l'esito, l'IP sorgente della
richiesta e un piccolo oggetto `detail` strutturato (ad esempio il nuovo stato
dell'alert o il formato di export).

### Cosa non viene volutamente registrato

Il registro conserva **attribuzione e metadata, mai il contenuto**: i corpi
delle note dell'operatore e i payload controllati dall'attaccante non vi
vengono mai copiati (una nota di alert/caso registra solo la sua lunghezza o
nulla). Così il registro resta utile senza diventare una seconda copia illimitata
di dati personali o input ostile.

### Garanzie di sola aggiunta

- Le righe sono **immutabili**: un trigger SQLite `BEFORE UPDATE`
  (`operator_audit_log_no_update`) rifiuta qualsiasi modifica in loco.
- L'`id` è un `AUTOINCREMENT` monotòno, quindi una cancellazione fuori banda di
  una riga intermedia è visibile come lacuna.
- Le uniche cancellazioni sono **potature limitate, dalle più vecchie**,
  anch'esse registrate come voce `audit.retention_prune` (la perdita di evidenza
  è esplicita, mai silenziosa).
- L'audit non interrompe mai l'azione che registra: la richiesta è già
  riuscita, perciò un errore di logging viene assorbito e riportato nel log
  applicativo invece di diventare un 5xx.

È a prova di manomissione a livello applicativo; come la catena di hash degli
eventi **non** difende da un attaccante che riscrive l'intero database.

### Lettura del registro

`GET /api/v1/audit` (autenticato come operatore) restituisce le voci più
recenti, dalla più nuova, con filtri opzionali `operator`, `action`,
`target_type`, `target_id` e `limit`, oltre a `retention_days` e `max_rows`
configurati.

Il registro è esposto in due punti per l'operatore:

- **Dashboard → vista Audit.** Un workspace dedicato elenca le voci in una
  tabella (timestamp, operatore, azione, target, esito, IP sorgente, dettaglio)
  con gli stessi filtri operatore/azione/target e il riepilogo di conservazione.
  Ogni campo è reso come testo, mai come HTML, così gli ID target e i valori di
  dettaglio forniti dall'operatore non possono iniettare markup.
- **Report del caso.** Il report del caso in JSON e Markdown include una sezione
  `operator_audit` limitata a quel caso (`target_type=case`,
  `target_id=<id caso>`): chi ha creato, modificato, collegato/rimosso evidenze,
  annotato o esportato il caso, attribuito all'operatore autenticato. Completa
  la history del caso così che il report sia un record di accountability
  completo. (Il CSV resta una tabella piatta di evidenze.)

### Configurazione

| Variabile | Default | Significato |
|---|---|---|
| `AEGIS_AUDIT_LOG_RETENTION_DAYS` | `365` | Limite di età; `0` disabilita la potatura per età. Volutamente superiore alla retention della telemetria per mantenere attribuibili le azioni. |
| `AEGIS_AUDIT_LOG_MAX_ROWS` | `1000000` | Limite di righe; `0` disabilita il limite di conteggio. |

L'identità operatore e l'IP sorgente della richiesta sono dati personali; vedi
[`PRIVACY.md`](PRIVACY.md) per conservazione e trattamento.
