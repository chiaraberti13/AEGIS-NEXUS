# Investigation workflow / Flusso investigativo

## English

AEGIS-NEXUS is evidence-first. The operator workflow is:

`Dashboard → event → IP → session → timeline → credentials/commands/payloads → external enrichment → MITRE/CVE/IOC → relationships → case → report → Study Mode`

### Dashboard

Global search and filters apply to both analytics and the Live Feed for the selected time window. Charts are analytical controls, not decoration: country, protocol, service and honeypot bars can be used to apply filters, while ASN, port, credential, command, IDS and MITRE values can drive a focused search.

The Attack Map uses only geolocation enrichment already attached to events. A point can be selected to focus the investigation on its source IP. Map placement is contextual infrastructure information, not attribution.

### Event investigation

Selecting an event preserves four separate evidence classes:

1. **Observed** — data directly captured by the honeypot/IDS.
2. **External enrichment** — provider data carrying `source` and `observed_at`.
3. **Derived** — evidence-backed IOC, MITRE or CVE analysis.
4. **Hypotheses** — analyst hypotheses that must remain visibly distinct from facts.

### IP and session analysis

The IP profile summarizes first/last observation, services, ports, sessions, ASN/country context and stored external enrichment. The session panel reconstructs the correlated sequence and exposes credential attempts, commands, payloads, IDS alerts and evidence-backed mappings.

Session correlation prefers an explicit per-connection sensor ID when a decoy provides one, or a Suricata `flow_id` combined with `flow.start` when available. Only when neither is present does AEGIS fall back to source IP, honeypot, service, protocol, destination port and an inactivity window. The UI exposes the method used. Correlation groups telemetry; it never proves common human identity.

### Threat Intelligence

AEGIS does not invent reputation, malware family, actor or campaign information. The Threat Intelligence panel displays only enrichment present in the dataset and always keeps provider and timestamp visible. Empty enrichment produces an empty panel rather than an inferred classification.

Local threat context exact matches, when configured, appear as external enrichment. They mean that an observed value is present in the operator-supplied feed; they do not change event severity and are not automatic evidence of compromise, attribution, MITRE technique or CVE.

### Observed artifact extraction

Commands and payloads are scanned statically for exact URLs, domains, IP literals and MD5/SHA-1/SHA-256-shaped values. Extracted items are deterministic derived data with an evidence path. They are useful for cross-session correlation and search, but their presence alone is not a maliciousness or compromise verdict.

### Relationship graph

The graph can contain event, session, IP, ASN, country, service, protocol, port, honeypot, credential, command, payload, IDS, IOC, MITRE and CVE nodes. Nodes exist only when the underlying data exists. MITRE and CVE nodes therefore appear only when the stored record contains rationale and evidence.

### Historical navigation

The investigation feed uses cursor pagination ordered by event timestamp plus event ID. The cursor freezes the initial time-window boundary and is bound to the active search and exact filters, preventing accidental reuse after the analyst changes scope. New telemetry arriving while older pages are being loaded does not shift already-issued cursors or create offset-style duplicates.

Session listing APIs use the same keyset approach with `last_seen` plus session ID. Cursors are navigation state, not evidence and not authorization tokens.

### Case management

Cases let an operator preserve the investigation context without duplicating hostile telemetry. Status, severity, summary, tags and notes are analyst-owned metadata. Event/session evidence is linked by identifier and can later become unavailable when normal telemetry retention removes its source. This is shown explicitly rather than interpreted as absence of activity. See [Case management](CASE_MANAGEMENT.md).

### Reporting

JSON reports preserve the complete evidence model. CSV reports provide a flat event timeline for analysis/export. Markdown reports provide a bilingual human-readable SOC handoff while preserving provenance sections and escaping hostile content. JSON, CSV and Markdown credential exports deliberately omit cleartext passwords. Dashboard statistics can also be exported as JSON. See [Investigation reporting](REPORTING.md).

### Study Mode

Event Study Mode explains why the selected evidence matters, what a SOC analyst should check next and which questions remain open. Session Study Mode works on the full correlated sequence and explicitly states analytical limitations.

---

## Italiano

AEGIS-NEXUS segue un approccio evidence-first. Il flusso operativo è:

`Dashboard → evento → IP → sessione → timeline → credential/comandi/payload → enrichment esterno → MITRE/CVE/IOC → relazioni → caso → report → Study Mode`

### Dashboard

Ricerca globale e filtri vengono applicati sia alle statistiche sia al Live Feed nella finestra temporale selezionata. I grafici sono controlli analitici, non elementi decorativi: paese, protocollo, servizio e honeypot possono applicare filtri; ASN, porta, credential, comando, IDS e MITRE possono avviare ricerche mirate.

L'Attack Map utilizza esclusivamente la geolocalizzazione già presente negli enrichment. Un punto può essere selezionato per concentrare l'investigazione sul relativo IP sorgente. La posizione è contesto infrastrutturale e non attribuzione.

### Investigazione dell'evento

La selezione di un evento mantiene separate quattro classi:

1. **Osservato** — dati catturati direttamente da honeypot/IDS.
2. **Enrichment esterno** — dati di provider con `source` e `observed_at`.
3. **Derivato** — IOC, MITRE o CVE supportati da evidenza.
4. **Ipotesi** — ipotesi analitiche che devono restare visibilmente separate dai fatti.

### Analisi IP e sessione

Il profilo IP riassume prima/ultima osservazione, servizi, porte, sessioni, contesto ASN/paese ed enrichment esterni memorizzati. Il pannello sessione ricostruisce la sequenza correlata ed evidenzia tentativi di credenziali, comandi, payload, alert IDS e mapping supportati da evidenza.

La correlazione preferisce un ID esplicito per connessione quando fornito dal decoy, oppure il `flow_id` Suricata combinato con `flow.start` quando disponibile. Solo in assenza di entrambi AEGIS usa il fallback con IP sorgente, honeypot, servizio, protocollo, porta destinazione e finestra di inattività. L'interfaccia mostra il metodo utilizzato. La correlazione raggruppa telemetria e non dimostra un'identità umana comune.

### Threat Intelligence

AEGIS non inventa reputazione, malware family, actor o campagne. Il pannello Threat Intelligence visualizza soltanto enrichment presenti nel dataset e mantiene sempre visibili provider e timestamp. In assenza di enrichment il pannello resta vuoto invece di produrre classificazioni inferite.

I match esatti del threat context locale, quando configurati, compaiono come enrichment esterno. Indicano che un valore osservato è presente nel feed fornito dall'operatore; non cambiano la severità e non costituiscono automaticamente prova di compromissione, attribuzione, tecnica MITRE o CVE.

### Estrazione artefatti osservati

Comandi e payload vengono analizzati staticamente per URL, domini, IP letterali e valori con forma MD5/SHA-1/SHA-256. Gli elementi estratti sono dati derivati deterministici con percorso di evidenza. Sono utili per correlazione tra sessioni e ricerca, ma la loro presenza non costituisce da sola un verdetto di malevolenza o compromissione.

### Grafo delle relazioni

Il grafo può contenere nodi evento, sessione, IP, ASN, paese, servizio, protocollo, porta, honeypot, credential, comando, payload, IDS, IOC, MITRE e CVE. I nodi esistono solo se esistono i dati corrispondenti. MITRE e CVE compaiono quindi soltanto quando il record contiene razionale ed evidenza.

### Navigazione storica

Il feed investigativo usa paginazione a cursore ordinata per timestamp evento più ID evento. Il cursore congela il limite temporale della prima pagina ed è vincolato a ricerca e filtri esatti attivi, evitando il riuso accidentale dopo un cambio di scope. La nuova telemetria che arriva mentre si caricano pagine precedenti non sposta i cursori già emessi e non produce i duplicati tipici della paginazione a offset.

Le API delle sessioni usano lo stesso approccio keyset con `last_seen` più ID sessione. I cursori sono stato di navigazione, non evidenza e non token di autorizzazione.

### Gestione casi

I casi permettono di conservare il contesto investigativo senza duplicare la telemetria ostile. Stato, severità, sintesi, tag e note sono metadati dell'analista. Eventi e sessioni vengono collegati per identificativo e possono diventare non disponibili quando la normale retention elimina la sorgente. Questa condizione viene mostrata esplicitamente e non interpretata come assenza di attività. Consulta [Gestione casi](CASE_MANAGEMENT.md).

### Reporting

I report JSON preservano il modello completo delle evidenze. I report CSV forniscono una timeline piatta utile per analisi/esportazione e omettono deliberatamente le password in chiaro. Anche le statistiche della dashboard possono essere esportate in JSON.

### Study Mode

Lo Study Mode dell'evento spiega perché l'evidenza selezionata è interessante, cosa dovrebbe controllare un SOC Analyst e quali domande restano aperte. Lo Study Mode della sessione lavora sull'intera sequenza correlata e rende espliciti i limiti dell'analisi.
