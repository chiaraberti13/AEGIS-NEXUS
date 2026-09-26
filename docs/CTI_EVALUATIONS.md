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
