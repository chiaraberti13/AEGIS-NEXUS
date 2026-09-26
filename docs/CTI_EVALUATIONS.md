# CTI integration evaluations / Valutazioni integrazioni CTI

## TAXII 2.1 client support

### English

**Status:** evaluated; suitable for a future opt-in provider, but not enabled by default.

AEGIS already has a provider boundary and conservative STIX 2.1 import/export. TAXII 2.1 is therefore a good transport candidate for remote CTI collections because it defines a RESTful application-layer API designed for CTI exchange and aligns naturally with STIX 2.1.

Reference: OASIS TAXII 2.1 Standard, 10 June 2021:
https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Recommended AEGIS scope:

- implement **read-only pull first** (API Root discovery, Collections, Get Objects);
- require explicit operator opt-in and never make network requests from the default local provider;
- require HTTPS by default and reject credentials embedded in URLs;
- keep TAXII credentials in deployment secrets/environment, never telemetry or exported evidence;
- apply strict response byte, object-count, pagination and request-time limits;
- preserve TAXII server/API-root/collection identity and retrieval timestamp as provenance;
- pass received STIX through the same conservative importer used for local bundles;
- ignore unsupported STIX objects/patterns instead of converting them into attribution;
- expose provider health without exposing authentication material;
- use bounded retry/backoff and fail enrichment independently from telemetry ingestion.

**Push/publication is intentionally deferred.** Sending CTI outward requires the roadmap's TLP/sharing-policy controls and export sanitization first, so AEGIS cannot accidentally disclose sensor-internal data, operator notes or other non-shareable context.

A TAXII client must run from the collector/provider side only. Decoy containers must never receive Internet egress to fetch intelligence.

### Italiano

**Stato:** valutato; adatto come futuro provider opt-in, ma non abilitato di default.

AEGIS dispone già di un confine provider e di import/export STIX 2.1 conservativi. TAXII 2.1 è quindi un buon candidato come trasporto per collection CTI remote, perché definisce una API REST applicativa per lo scambio di Cyber Threat Intelligence ed è naturalmente allineato a STIX 2.1.

Riferimento: standard OASIS TAXII 2.1, 10 giugno 2021:
https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Per AEGIS è raccomandato:

- implementare prima un client **read-only pull** (discovery API Root, Collections, Get Objects);
- richiedere opt-in esplicito dell'operatore e non introdurre richieste di rete nel provider locale predefinito;
- richiedere HTTPS di default e rifiutare credenziali inserite nelle URL;
- mantenere le credenziali TAXII nei secret/environment di deployment, mai nella telemetria o nelle evidenze esportate;
- applicare limiti rigidi a byte di risposta, numero oggetti, paginazione, richieste e timeout;
- conservare server/API root/collection e timestamp di retrieval come provenienza;
- passare lo STIX ricevuto attraverso lo stesso importer conservativo usato per i bundle locali;
- ignorare oggetti/pattern STIX non supportati invece di convertirli in attribuzione;
- esporre lo stato del provider senza mostrare materiale di autenticazione;
- usare retry/backoff bounded e mantenere eventuali errori CTI indipendenti dall'ingestione della telemetria.

Il **push/pubblicazione resta intenzionalmente rinviato**. Prima di inviare CTI verso l'esterno devono essere completati i controlli TLP/sharing policy e la sanitizzazione degli export previsti dalla roadmap, così AEGIS non può divulgare accidentalmente dati interni dei sensori, note operatore o altro contesto non condivisibile.

Un client TAXII dovrà essere eseguito soltanto lato collector/provider. I container decoy non devono ottenere egress Internet per scaricare intelligence.


---

## MISP export/import

### English

**Status:** evaluated; interoperable through AEGIS STIX 2.1 now, with native MISP-format integration deferred.

Official MISP documentation describes an extensive REST/OpenAPI interface, a stable MISP standard JSON format, and import/export support including STIX 1.x/2.x. Current MISP releases also continue to invest in STIX interoperability.

References:

- MISP documentation and format specifications: https://www.misp-project.org/documentation/
- MISP features / import-export capabilities: https://www.misp-project.org/features/
- MISP tools, including PyMISP and MISP-STIX-Converter: https://www.misp-project.org/tools/

Recommended AEGIS integration path:

1. **Use STIX 2.1 as the first MISP interoperability boundary.** AEGIS already has bounded conservative STIX import/export, while MISP supports STIX import/export. This avoids duplicating a second conversion layer before sharing controls exist.
2. Treat MISP-originated STIX as external CTI enrichment, never as observed honeypot evidence.
3. Continue importing only exact supported indicators. Do not turn MISP Galaxy, threat-actor, campaign, relationship or vulnerability objects into attribution, ATT&CK or CVE assertions unless a future explicitly provenance-aware feature is designed for those object types.
4. Do not automatically publish AEGIS data to MISP yet. Outbound publication must wait for TLP/sharing-policy enforcement and shareable-export sanitization.
5. If native MISP JSON/API support is later required, implement it as a separate opt-in provider/transport using the common CTI boundary, bounded requests and explicit MISP event/attribute provenance. Prefer the official PyMISP/API ecosystem rather than reimplementing MISP semantics.

**Decision:** no native MISP parser or network client is added in this cycle. Existing STIX 2.1 import/export is the supported bridge for controlled MISP interoperability. Re-evaluate native MISP support only when a concrete deployment requires MISP-specific event/object semantics.

### Italiano

**Stato:** valutato; interoperabilità disponibile tramite STIX 2.1 di AEGIS, mentre l'integrazione nativa del formato MISP resta rinviata.

La documentazione ufficiale MISP descrive una REST/OpenAPI estesa, un formato JSON standard MISP stabile e supporto import/export che comprende STIX 1.x/2.x. Le release MISP attuali continuano inoltre a sviluppare l'interoperabilità STIX.

Riferimenti:

- Documentazione e specifiche dei formati MISP: https://www.misp-project.org/documentation/
- Funzionalità MISP / capacità import-export: https://www.misp-project.org/features/
- Tool MISP, inclusi PyMISP e MISP-STIX-Converter: https://www.misp-project.org/tools/

Percorso raccomandato per AEGIS:

1. **Usare STIX 2.1 come primo confine di interoperabilità MISP.** AEGIS dispone già di import/export STIX conservativi e bounded, mentre MISP supporta import/export STIX. Si evita così di duplicare un secondo livello di conversione prima di avere i controlli di condivisione.
2. Trattare lo STIX proveniente da MISP come CTI esterna di enrichment, mai come evidenza osservata dall'honeypot.
3. Continuare a importare soltanto indicatori exact-match supportati. Galaxy MISP, threat actor, campagne, relationship o vulnerability non devono diventare automaticamente attribuzione, ATT&CK o CVE.
4. Non pubblicare ancora automaticamente dati AEGIS verso MISP. La pubblicazione outbound deve attendere enforcement TLP/sharing policy e sanitizzazione degli export condivisibili.
5. Se in futuro servirà supporto MISP JSON/API nativo, implementarlo come provider/trasporto opt-in separato attraverso il confine CTI comune, con richieste bounded e provenance esplicita di eventi/attributi MISP. È preferibile usare l'ecosistema ufficiale PyMISP/API anziché reimplementare la semantica MISP.

**Decisione:** in questo ciclo non viene aggiunto un parser MISP nativo né un client di rete. L'import/export STIX 2.1 esistente è il bridge supportato per interoperabilità MISP controllata. Il supporto MISP nativo verrà rivalutato solo davanti a un requisito di deployment concreto che richieda semantiche specifiche di eventi/oggetti MISP.
