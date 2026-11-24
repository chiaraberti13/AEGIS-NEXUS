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

### Evidence bundle (chain of custody)

`GET /api/v1/reports/case/<case_id>/bundle.zip` (operator-authenticated, audited)
returns a ZIP containing the case report (JSON + Markdown), one JSON file per
referenced evidence record (the full stored event/alert when available, or a
bounded summary), and a `manifest.json` listing the SHA-256 and byte length of
every other file. The manifest never hashes itself; the archive uses fixed
timestamps so identical inputs produce a byte-identical bundle. The bundle is
inert data served as an attachment — it is not rendered and executes nothing.
Because it may embed full events (source IPs, usernames, payloads) and the
case's operator audit trail, treat the download as sensitive.

### Redaction profiles

Session and case reports (JSON and Markdown) accept `?profile=internal`
(default, full detail) or `?profile=shareable`. The shareable profile masks
structured network identifiers (source IPs to their /24 or /48 network prefix),
removes usernames and operator/owner identities, and keeps SHA-256 fingerprints,
detection structure and evidence-backed MITRE/IOC context. It is **not** full
anonymization: free-text analyst fields and attacker-embedded identifiers inside
commands/payloads are left intact for review, and the Markdown export carries a
visible redaction banner. The chosen profile is recorded in the export audit
entry.

### Safe PDF export

Session and case reports can also be exported as PDF (`…/<id>.pdf`,
operator-authenticated and audited, honouring `?profile=` and `?lang=`). The PDF
is produced by a **pure-Python, text-only** writer: it uses no headless browser
and never renders HTML/CSS/JavaScript, so attacker-controlled report content
cannot execute or trigger fetches during export. Text is escaped for PDF
strings and encoded to Latin-1 (attacker bytes become inert glyphs). It is a
plain text rendering, not typeset layout.

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

### Evidence bundle (catena di custodia)

`GET /api/v1/reports/case/<case_id>/bundle.zip` (autenticato operatore, auditato)
restituisce uno ZIP con il report del caso (JSON + Markdown), un file JSON per
ogni evidenza referenziata (l'evento/alert completo memorizzato quando
disponibile, oppure un riepilogo limitato) e un `manifest.json` che elenca
SHA-256 e lunghezza in byte di ogni altro file. Il manifest non calcola l'hash
di sé stesso; l'archivio usa timestamp fissi così input identici producono un
bundle identico byte-per-byte. Il bundle è dato inerte servito come attachment —
non viene renderizzato e non esegue nulla. Poiché può includere eventi completi
(IP sorgente, username, payload) e la traccia di audit operatore del caso, il
download va trattato come sensibile.

### Profili di redazione

I report di sessione e caso (JSON e Markdown) accettano `?profile=internal`
(default, dettaglio completo) o `?profile=shareable`. Il profilo condivisibile
maschera gli identificatori di rete strutturati (IP sorgente al prefisso di rete
/24 o /48), rimuove username e identità operatore/responsabile, e mantiene i
fingerprint SHA-256, la struttura di detection e il contesto MITRE/IOC
evidence-backed. **Non** è un'anonimizzazione completa: i campi free-text
dell'analista e gli identificatori inseriti dall'attaccante dentro
comandi/payload restano intatti per revisione, e l'export Markdown porta un
banner di redazione visibile. Il profilo scelto è registrato nella voce di audit
dell'export.

### Export PDF sicuro

Session e case report sono esportabili anche in PDF (`…/<id>.pdf`,
operatore-autenticato e auditato, con `?profile=` e `?lang=`). Il PDF è generato
da un writer **puro-Python di solo testo**: non usa alcun headless browser e non
rende MAI HTML/CSS/JavaScript, quindi il contenuto controllato dall'attaccante
non può eseguire né innescare fetch durante l'export. Il testo è escapato per le
stringhe PDF e codificato in Latin-1 (i byte dell'attaccante diventano glifi
inerti). È un rendering testuale semplice, non tipografico.

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
