# Investigation reporting / Reporting investigativo

## English

AEGIS-NEXUS provides three investigation export formats:

- **JSON** for complete structured machine-readable investigation data.
- **CSV** for flat event review and spreadsheet workflows.
- **Markdown** for human-readable SOC handoff, notes and documentation.

Markdown reports preserve the evidence model rather than flattening everything into a single narrative. Session reports separate observed credentials, commands and payloads from external enrichment and derived IOC/MITRE/CVE context. Case reports explicitly label case fields and notes as analyst-owned classifications or annotations.

### Safety boundaries

Markdown is generated only from the already export-sanitized session/case report structures.

- cleartext credential passwords are never included, even when raw credential storage was explicitly enabled;
- attacker-controlled and analyst-controlled strings are escaped before Markdown rendering;
- commands, payloads and structured hostile data are rendered as HTML-escaped indented code blocks;
- the session event appendix is limited to 200 events to bound generated file size;
- Markdown export does not execute payloads, resolve URLs, enrich data or infer attribution;
- case Markdown contains evidence references, not copied source telemetry.

The report language follows the console language when downloaded from the UI. The API accepts `?lang=it` or `?lang=en`.

---

## Italiano

AEGIS-NEXUS fornisce tre formati di export investigativo:

- **JSON** per dati investigativi strutturati e machine-readable.
- **CSV** per revisione tabellare degli eventi e workflow con fogli di calcolo.
- **Markdown** per handoff SOC, note e documentazione leggibile.

I report Markdown mantengono il modello di evidenza invece di fondere tutto in un'unica narrazione. I report di sessione separano credential, comandi e payload osservati da enrichment esterni e contesto derivato IOC/MITRE/CVE. I report dei casi marcano esplicitamente campi e note come classificazioni o annotazioni dell'analista.

### Confini di sicurezza

Il Markdown viene generato esclusivamente dalle strutture di report sessione/caso già sanitizzate per l'export.

- le password in chiaro non vengono mai incluse, anche quando lo storage raw delle credenziali è stato esplicitamente abilitato;
- le stringhe controllate dall'attaccante o dall'analista vengono escapate prima del rendering Markdown;
- comandi, payload e dati ostili strutturati sono rappresentati come blocchi di codice indentati e HTML-escaped;
- l'appendice eventi della sessione è limitata a 200 eventi per contenere la dimensione del file;
- l'export Markdown non esegue payload, non risolve URL, non effettua enrichment e non deduce attribuzione;
- il Markdown dei casi contiene riferimenti alle evidenze, non copie della telemetria sorgente.

Dall'interfaccia il report usa la lingua attiva della console. L'API accetta `?lang=it` oppure `?lang=en`.
