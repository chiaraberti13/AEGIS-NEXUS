# Investigation workflow / Flusso investigativo

## English

AEGIS-NEXUS is evidence-first. The operator workflow is:

`Dashboard → Alerts / IOC → event → IP → session → timeline → evidence pivots → relationships → case → report → Study Mode`

### Dashboard

Global search and filters apply to both analytics and the Live Feed for the selected time window. Charts are analytical controls, not decoration: attacks over time, unique source IPs over time, top sources, event type, severity, country, ASN, destination port, protocol, service, honeypot, usernames, safe password fingerprints, commands, payloads, IDS, IOC, evidence-backed MITRE/CVE and the temporal heatmap are all derived from the active scope. Filterable dimensions apply exact filters; artifact panels drive focused searches.

The Attack Map uses only geolocation enrichment already attached to events and aggregates repeated observations for the same source/location. Point metadata can include count, sessions, services, ports, ASN and last-seen context. Selecting a point focuses the investigation on its source IP. Map placement is contextual infrastructure information, not attribution.

### Event investigation

Selecting an event preserves four separate evidence classes:

1. **Observed** — data directly captured by the honeypot/IDS.
2. **External enrichment** — provider data carrying `source` and `observed_at`.
3. **Derived** — evidence-backed IOC, MITRE or CVE analysis.
4. **Hypotheses** — analyst hypotheses that must remain visibly distinct from facts.

### IP and session analysis

The IP profile summarizes first/last observation, services, ports, sessions, ASN/country context, event types, honeypots, usernames, safe password fingerprints, commands, payloads, IDS, IOC/MITRE/CVE activity and stored external enrichment. The session panel reconstructs the correlated sequence and exposes credential attempts, commands, payloads, IDS alerts and evidence-backed mappings.

Session correlation prefers an explicit per-connection sensor ID when a decoy provides one, or a Suricata `flow_id` combined with `flow.start` when available. Only when neither is present does AEGIS fall back to source IP, honeypot, service, protocol, destination port and an inactivity window. The UI exposes the method used. Correlation groups telemetry; it never proves common human identity.

Cross-session correlation is a separate deterministic investigation layer. It can compare retained sessions through exact source IP, username, safe credential-secret fingerprint, command/payload SHA-256, derived IOC (including URL/domain artifacts), Suricata signature, ASN, service and destination port. Every result stores the method, score, strength and concrete event-level evidence basis in `correlation_links`. The score expresses evidence overlap only; it is never an identity, actor or attribution probability.

### Threat Intelligence

AEGIS does not invent reputation, malware family, actor or campaign information. The external-context panel keeps provider and timestamp visible and distinguishes contextual enrichment such as GeoIP/ASN from true Threat Intelligence records originating from `enrichment.threat_context`. Empty data produces an empty panel rather than an inferred classification.

Local threat context exact matches, when configured, appear as external enrichment. They mean that an observed value is present in the operator-supplied feed; they do not change event severity and are not automatic evidence of compromise, attribution, MITRE technique or CVE.

### Observed artifact extraction

Commands and payloads are scanned statically for exact URLs, domains, IP literals and MD5/SHA-1/SHA-256-shaped values. Extracted items are deterministic derived data with an evidence path. They are useful for cross-session correlation and search, but their presence alone is not a maliciousness or compromise verdict.

### IOC Workspace

The IOC Workspace aggregates only deterministic artifacts already present in `derived.ioc`. Each indicator receives a stable content-derived ID and exposes type/value, first seen, last seen, occurrence count, source IPs, sessions, honeypots, services and source event references. Detail pivots also expose related alert and case IDs when those relationships exist.

The workspace is bounded by the selected time window and `ANALYTICS_MAX_EVENTS`. A truncation flag is returned when the event analysis cap is reached. Search and type filters can be exported as formula-safe CSV without exposing credential secrets. IOC are derived artifacts: they are not reputation, Threat Intelligence, compromise verdicts or attribution.

### Relationship graph

The graph can contain event, session, IP, ASN, country, service, protocol, port, honeypot, username, safe credential-secret fingerprint, command, payload, IDS, IOC, external Threat Intelligence, MITRE and CVE nodes. Every node carries provenance (`observed`, `enrichment` or `derived`) and may expose bounded evidence metadata in the inspector. Nodes exist only when the underlying data exists. MITRE and CVE nodes therefore appear only when the stored record contains rationale and evidence.

Graph controls can restrict the visible node type, traversal depth and evidence scope. Evidence-only mode removes enrichment nodes while preserving observed telemetry and deterministic derived evidence. Edge provenance follows the target evidence class and is rendered separately from node provenance. These controls change presentation only; they do not create new relationships.

### Historical navigation

The investigation feed uses cursor pagination ordered by event timestamp plus event ID. The cursor freezes the initial time-window boundary and is bound to the active search and exact filters, preventing accidental reuse after the analyst changes scope. New telemetry arriving while older pages are being loaded does not shift already-issued cursors or create offset-style duplicates.

Session listing APIs use the same keyset approach with `last_seen` plus session ID. Cursors are navigation state, not evidence and not authorization tokens.

### Large-session analysis bounds

A single correlated session can be attacker-amplified. `AEGIS_SESSION_MAX_EVENTS` therefore bounds how many session events are loaded into one timeline, relationship graph, report or Study Mode request. If the retained session is larger, AEGIS uses the latest bounded subset and returns explicit `analysis.truncated`, `event_limit` and scope metadata. The console and generated analysis surface that limitation; a truncated view must not be described as the complete session.

### Case management

Cases let an operator preserve the investigation context without duplicating hostile telemetry. Status, severity, summary, tags and notes are analyst-owned metadata. Event/session/alert evidence is linked by identifier and can later become unavailable when normal telemetry retention removes its source. This is shown explicitly rather than interpreted as absence of activity. See [Case management](CASE_MANAGEMENT.md).

### Reporting

JSON reports preserve the complete evidence model. CSV reports provide a flat event timeline for analysis/export. Markdown reports provide a bilingual human-readable SOC handoff while preserving provenance sections and escaping hostile content. JSON, CSV and Markdown credential exports deliberately omit cleartext passwords. Dashboard statistics can also be exported as JSON. See [Investigation reporting](REPORTING.md).

### Study Mode

Event Study Mode explains why the selected evidence matters, what a SOC analyst should check next and which questions remain open. Session Study Mode works on the full correlated sequence and explicitly states analytical limitations.

---

## Italiano

AEGIS-NEXUS segue un approccio evidence-first. Il flusso operativo è:

`Dashboard → Alert / IOC → evento → IP → sessione → timeline → pivot di evidenza → relazioni → caso → report → Study Mode`

### Dashboard

Ricerca globale e filtri vengono applicati sia alle statistiche sia al Live Feed nella finestra temporale selezionata. I grafici sono controlli analitici, non elementi decorativi: attacks over time, IP sorgente unici nel tempo, top source, tipo evento, severità, paese, ASN, porta destinazione, protocollo, servizio, honeypot, username, fingerprint password sicuri, comandi, payload, IDS, IOC, MITRE/CVE supportati da evidenza e heatmap temporale derivano tutti dallo scope attivo. Le dimensioni filtrabili applicano filtri esatti; i pannelli artefatto avviano ricerche mirate.

L'Attack Map utilizza esclusivamente la geolocalizzazione già presente negli enrichment e aggrega osservazioni ripetute della stessa sorgente/posizione. I metadata del punto possono includere conteggio, sessioni, servizi, porte, ASN e ultima osservazione. Selezionare un punto concentra l'investigazione sul relativo IP sorgente. La posizione è contesto infrastrutturale e non attribuzione.

### Investigazione dell'evento

La selezione di un evento mantiene separate quattro classi:

1. **Osservato** — dati catturati direttamente da honeypot/IDS.
2. **Enrichment esterno** — dati di provider con `source` e `observed_at`.
3. **Derivato** — IOC, MITRE o CVE supportati da evidenza.
4. **Ipotesi** — ipotesi analitiche che devono restare visibilmente separate dai fatti.

### Analisi IP e sessione

Il profilo IP riassume prima/ultima osservazione, servizi, porte, sessioni, contesto ASN/paese, tipi evento, honeypot, username, fingerprint password sicuri, comandi, payload, IDS, attività IOC/MITRE/CVE ed enrichment esterni memorizzati. Il pannello sessione ricostruisce la sequenza correlata ed evidenzia tentativi di credenziali, comandi, payload, alert IDS e mapping supportati da evidenza.

La correlazione preferisce un ID esplicito per connessione quando fornito dal decoy, oppure il `flow_id` Suricata combinato con `flow.start` quando disponibile. Solo in assenza di entrambi AEGIS usa il fallback con IP sorgente, honeypot, servizio, protocollo, porta destinazione e finestra di inattività. L'interfaccia mostra il metodo utilizzato. La correlazione raggruppa telemetria e non dimostra un'identità umana comune.

La correlazione tra sessioni è un livello investigativo deterministico separato. Può confrontare le sessioni conservate tramite IP sorgente esatto, username, fingerprint sicuro del segreto credential, SHA-256 di comandi/payload, IOC derivati (inclusi artefatti URL/dominio), signature Suricata, ASN, servizio e porta destinazione. Ogni risultato memorizza metodo, score, forza e basis di evidenza a livello evento in `correlation_links`. Lo score descrive esclusivamente sovrapposizione di evidenze e non è mai una probabilità di identità, actor o attribuzione.

### Threat Intelligence

AEGIS non inventa reputazione, malware family, actor o campagne. Il pannello di contesto esterno mantiene sempre visibili provider e timestamp e distingue enrichment contestuale come GeoIP/ASN dalla vera Threat Intelligence proveniente da `enrichment.threat_context`. In assenza di dati il pannello resta vuoto invece di produrre classificazioni inferite.

I match esatti del threat context locale, quando configurati, compaiono come enrichment esterno. Indicano che un valore osservato è presente nel feed fornito dall'operatore; non cambiano la severità e non costituiscono automaticamente prova di compromissione, attribuzione, tecnica MITRE o CVE.

### Estrazione artefatti osservati

Comandi e payload vengono analizzati staticamente per URL, domini, IP letterali e valori con forma MD5/SHA-1/SHA-256. Gli elementi estratti sono dati derivati deterministici con percorso di evidenza. Sono utili per correlazione tra sessioni e ricerca, ma la loro presenza non costituisce da sola un verdetto di malevolenza o compromissione.

### IOC Workspace

L'IOC Workspace aggrega esclusivamente artefatti deterministici già presenti in `derived.ioc`. Ogni indicatore riceve un ID stabile derivato dal contenuto ed espone tipo/valore, prima e ultima osservazione, occorrenze, IP sorgente, sessioni, honeypot, servizi e riferimenti agli eventi sorgente. Il dettaglio mostra anche gli ID di alert e casi correlati quando tali relazioni esistono.

Lo workspace è limitato dalla finestra temporale selezionata e da `ANALYTICS_MAX_EVENTS`; quando viene raggiunto il limite viene restituito un flag di troncamento. Ricerca e filtro per tipo possono essere esportati in CSV con neutralizzazione delle formule e senza esporre segreti credential. Gli IOC sono artefatti derivati: non sono reputazione, Threat Intelligence, verdetti di compromissione o attribuzione.

### Grafo delle relazioni

Il grafo può contenere nodi evento, sessione, IP, ASN, paese, servizio, protocollo, porta, honeypot, username, fingerprint sicuro del segreto credential, comando, payload, IDS, IOC, Threat Intelligence esterna, MITRE e CVE. Ogni nodo espone la provenienza (`observed`, `enrichment` o `derived`) e può mostrare metadata di evidenza limitati nell'inspector. I nodi esistono solo se esistono i dati corrispondenti. MITRE e CVE compaiono quindi soltanto quando il record contiene razionale ed evidenza.

I controlli del grafo possono limitare il tipo di nodo visibile, la profondità di attraversamento e lo scope di evidenza. La modalità evidence-only rimuove i nodi di enrichment mantenendo telemetria osservata ed evidenza derivata deterministica. La provenance degli edge segue la classe di evidenza del nodo destinazione ed è resa separatamente dalla provenance dei nodi. Questi controlli modificano soltanto la visualizzazione e non creano nuove relazioni.

### Navigazione storica

Il feed investigativo usa paginazione a cursore ordinata per timestamp evento più ID evento. Il cursore congela il limite temporale della prima pagina ed è vincolato a ricerca e filtri esatti attivi, evitando il riuso accidentale dopo un cambio di scope. La nuova telemetria che arriva mentre si caricano pagine precedenti non sposta i cursori già emessi e non produce i duplicati tipici della paginazione a offset.

Le API delle sessioni usano lo stesso approccio keyset con `last_seen` più ID sessione. I cursori sono stato di navigazione, non evidenza e non token di autorizzazione.

### Limiti per sessioni molto grandi

Una singola sessione correlata può essere amplificata dall'attaccante. `AEGIS_SESSION_MAX_EVENTS` limita quindi il numero di eventi caricati in una singola richiesta di timeline, grafo relazionale, report o Study Mode. Se la sessione conservata è più grande, AEGIS usa il sottoinsieme più recente entro il limite e restituisce metadata espliciti `analysis.truncated`, `event_limit` e scope. Console e analisi generate mostrano questa limitazione; una vista troncata non deve essere descritta come sessione completa.

### Gestione casi

I casi permettono di conservare il contesto investigativo senza duplicare la telemetria ostile. Stato, severità, sintesi, tag e note sono metadati dell'analista. Eventi, sessioni e alert vengono collegati per identificativo e possono diventare non disponibili quando la normale retention elimina la sorgente. Questa condizione viene mostrata esplicitamente e non interpretata come assenza di attività. Consulta [Gestione casi](CASE_MANAGEMENT.md).

### Reporting

I report JSON preservano il modello completo delle evidenze. I report CSV forniscono una timeline piatta utile per analisi/esportazione e omettono deliberatamente le password in chiaro. Anche le statistiche della dashboard possono essere esportate in JSON.

### Study Mode

Lo Study Mode dell'evento spiega perché l'evidenza selezionata è interessante, cosa dovrebbe controllare un SOC Analyst e quali domande restano aperte. Lo Study Mode della sessione lavora sull'intera sequenza correlata e rende espliciti i limiti dell'analisi.
