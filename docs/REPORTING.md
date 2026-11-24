# Investigation reporting / Reporting investigativo

## English

AEGIS-NEXUS provides three investigation export formats:

- **JSON** for complete structured machine-readable investigation data.
- **CSV** for flat event review and spreadsheet workflows.
- **Markdown** for human-readable SOC handoff, notes and documentation.

Markdown reports preserve the evidence model rather than flattening everything into a single narrative. Session reports separate observed credentials, commands and payloads from external enrichment and derived IOC/MITRE/CVE context. Case reports explicitly label case fields and notes as analyst-owned classifications or annotations.

### SOC summary report

`GET /api/v1/reports/soc-summary` (operator-authenticated) produces a windowed
roll-up as JSON, and `…/soc-summary.md` as an audited Markdown download. The
window is a named preset — `?range=24h|7d|30d` — or an explicit `?hours=<n>`
custom range. The summary composes, over the window: observed event volume (by
severity, top enrichment countries/ASNs), detection statistics (per-rule hit
counts, open/closed, dispositions) and MTTA/MTTR response metrics, observed
evidence-backed MITRE techniques and the rule-coverage view, and derived IOC
artifacts. It always carries an explicit `evidence_integrity_warnings` list
(lossy normalization, credential redaction, a capped analytics window): an empty
list is disclosed as *no warnings in the window*, never as a completeness
guarantee. Geolocation/ASN stay enrichment and MITRE/IOC stay evidence-backed —
the summary asserts no attribution.

### Safety boundaries

Markdown is generated only from the already export-sanitized session/case report structures.

- cleartext credential passwords are never included, even when raw credential storage was explicitly enabled;
- attacker-controlled and analyst-controlled strings are escaped before Markdown rendering;
- commands, payloads and structured hostile data are rendered as HTML-escaped indented code blocks;
- the session event appendix is limited to 200 events to bound generated file size;
- Markdown export does not execute payloads, resolve URLs, enrich data or infer attribution;
- case Markdown contains evidence references, not copied source telemetry;
- case JSON and Markdown reports include an `operator_audit` section (the append-only operator audit log scoped to that case) for a complete accountability record; see [`AUDIT_LOG.md`](AUDIT_LOG.md).

The report language follows the console language when downloaded from the UI. The API accepts `?lang=it` or `?lang=en`.

---

## Italiano

AEGIS-NEXUS fornisce tre formati di export investigativo:

- **JSON** per dati investigativi strutturati e machine-readable.
- **CSV** per revisione tabellare degli eventi e workflow con fogli di calcolo.
- **Markdown** per handoff SOC, note e documentazione leggibile.

I report Markdown mantengono il modello di evidenza invece di fondere tutto in un'unica narrazione. I report di sessione separano credential, comandi e payload osservati da enrichment esterni e contesto derivato IOC/MITRE/CVE. I report dei casi marcano esplicitamente campi e note come classificazioni o annotazioni dell'analista.

### Riepilogo SOC

`GET /api/v1/reports/soc-summary` (autenticato operatore) produce un riepilogo
sulla finestra in JSON, e `…/soc-summary.md` come download Markdown auditato. La
finestra è un preset — `?range=24h|7d|30d` — oppure un intervallo personalizzato
`?hours=<n>`. Il riepilogo compone, sulla finestra: volume di eventi osservati
(per severità, top paesi/ASN di enrichment), statistiche di detection (hit count
per regola, aperti/chiusi, disposition) e metriche MTTA/MTTR, tecniche MITRE
osservate (evidence-backed) e la vista di coverage delle regole, e gli artefatti
IOC derivati. Porta sempre una lista esplicita `evidence_integrity_warnings`
(normalizzazione lossy, redazione credenziali, finestra analitica limitata): una
lista vuota è dichiarata come *nessun avviso nella finestra*, mai come garanzia
di completezza. Geolocalizzazione/ASN restano enrichment e MITRE/IOC restano
evidence-backed — il riepilogo non asserisce attribuzione.

### Confini di sicurezza

Il Markdown viene generato esclusivamente dalle strutture di report sessione/caso già sanitizzate per l'export.

- le password in chiaro non vengono mai incluse, anche quando lo storage raw delle credenziali è stato esplicitamente abilitato;
- le stringhe controllate dall'attaccante o dall'analista vengono escapate prima del rendering Markdown;
- comandi, payload e dati ostili strutturati sono rappresentati come blocchi di codice indentati e HTML-escaped;
- l'appendice eventi della sessione è limitata a 200 eventi per contenere la dimensione del file;
- l'export Markdown non esegue payload, non risolve URL, non effettua enrichment e non deduce attribuzione;
- il Markdown dei casi contiene riferimenti alle evidenze, non copie della telemetria sorgente;
- i report dei casi JSON e Markdown includono una sezione `operator_audit` (il registro di audit append-only dell'operatore limitato a quel caso) per un record di accountability completo; vedi [`AUDIT_LOG.md`](AUDIT_LOG.md).

Dall'interfaccia il report usa la lingua attiva della console. L'API accetta `?lang=it` oppure `?lang=en`.
