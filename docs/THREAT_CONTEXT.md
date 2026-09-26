# Local threat context / Threat context locale

## English

AEGIS-NEXUS can correlate observed IPs and derived artifacts against an operator-supplied local JSON feed. The adapter is offline and exact-match only.

The local JSON adapter implements the common `ThreatIntelligenceProvider` contract (`provider_id`, network-use declaration, `status()`, `enrich()` and optional `close()`). This keeps the current offline behavior while allowing future providers to use the same collector boundary instead of adding provider-specific ingestion logic.

It performs **no network requests** and never sends honeypot IPs, URLs, domains or hashes to a third-party service.

### What a match means

A match means only that an exact observed value also exists in the configured external feed.

The result is stored in `enrichment.threat_context` with:
- the provider ID (`local-json`);
- the feed source;
- the feed retrieval/load timestamp;
- the enrichment timestamp;
- `match_policy: exact`;
- the feed timestamp when supplied;
- one or more matched indicators;
- the evidence path that produced the candidate, such as `observed.source_ip` or `observed.command`.

A match does **not** automatically:
- raise event severity;
- create a MITRE ATT&CK mapping;
- create a CVE;
- identify a malware family;
- attribute activity to an actor or campaign;
- prove compromise or malicious intent.

### Provider trust and limitations

Threat Intelligence is external context, not ground truth. AEGIS records provider/source/retrieval provenance so analysts can judge where a claim came from and how old it was. Feed labels and confidence remain source-supplied metadata; AEGIS does not promote them into observed facts. Provider matches cannot mutate \`observed\`, cannot create attribution, and cannot create ATT&CK/CVE relationships. Network-backed providers, if added later, must declare network use explicitly and remain independent from telemetry ingestion failures.

### Supported exact indicator types

- `ip`
- `domain`
- `url`
- `md5`
- `sha1`
- `sha256`

Domains and hash values are normalized conservatively. URLs normalize scheme and host while preserving path, query and fragment. Unsupported or invalid records are skipped.

### Feed format

The feed root is a JSON object:

```json
{
  "source": "example-local-feed",
  "generated_at": "2026-09-22T20:00:00Z",
  "indicators": [
    {
      "type": "ip",
      "value": "198.51.100.10",
      "labels": ["scanner"],
      "confidence": 70,
      "description": "Example documentation record",
      "reference": "https://example.invalid/indicator/1",
      "first_seen": "2026-09-20T00:00:00Z",
      "last_seen": "2026-09-22T00:00:00Z"
    }
  ]
}
```

The example uses documentation-only data and is not shipped as live threat intelligence.

### Benign scanner context

Operators may mount a local JSON list through \`AEGIS_BENIGN_SCANNER_FILE\` using entries such as \`{"cidr":"198.51.100.0/24","name":"lab scanner"}\`. Matching source IPs receive \`enrichment.benign_scanner_context\` with source/retrieval provenance, \`context_only: true\` and \`suppression: false\`. The match never changes severity, drops telemetry, suppresses detections or closes alerts. File size and entry count are bounded.

### Indicator aging and decay

AEGIS preserves source-supplied confidence unchanged and derives freshness separately. When a match has \`last_seen\`, \`first_seen\`, or a feed \`generated_at\` timestamp, the stored match receives an \`aging\` block containing the timestamp basis, \`age_days\`, a \`fresh\` / \`stale\` / \`aged\` state and a deterministic \`freshness_score\` from 100 to 0. Defaults are 30 days before stale and 90 days before aged; configure them with \`AEGIS_CTI_STALE_AFTER_DAYS\` and \`AEGIS_CTI_AGED_AFTER_DAYS\`.

Source validity windows are reported independently as \`active\`, \`not_yet_valid\`, \`expired\` or \`unspecified\`. An aged or expired indicator is **not deleted and is not silently suppressed**: the historical match remains available with its evidence and source confidence, while the freshness metadata tells the analyst how old the CTI context was when enrichment occurred.

### Resource bounds

The loader applies:
- maximum feed byte size;
- maximum indicator count;
- maximum matches attached to one event;
- maximum duplicate records per exact indicator;
- bounded metadata strings and label counts.

Malformed or oversized feeds fail closed for threat-context enrichment: telemetry ingestion continues, but the adapter reports itself as unavailable.

### Docker Compose

Keep the feed outside Git:

```bash
mkdir -p threat-context
# Place feed.json inside ./threat-context
docker compose -f docker-compose.yml -f docker-compose.threat-context.yml up -d --build
```

The directory is mounted read-only.

Operator status is available at:

`GET /api/v1/threat-context/status`

### Custom JSON feed adapter

Non-native JSON feeds can be mapped into the canonical AEGIS indicator schema without custom Python code. Configure exactly one of:

- \`AEGIS_THREAT_CONTEXT_ADAPTER_FILE\` — preferred for deployments; point it to a read-only JSON configuration file.
- \`AEGIS_THREAT_CONTEXT_ADAPTER_JSON\` — bounded inline JSON for simple mappings.

The adapter is declarative only: dotted paths traverse object keys, and no \`eval\`, executable JSONPath, templates or dynamically imported code are supported. The configuration is capped at 16 KiB.

Example adapter:

\`\`\`json
{
  "items_path": "data.records",
  "source_path": "meta.vendor",
  "generated_at_path": "meta.created",
  "fields": {
    "type": "indicator.kind",
    "value": "indicator.observable",
    "confidence": "assessment.score",
    "labels": "assessment.tags"
  },
  "type_map": {
    "ipv4": "ip",
    "fqdn": "domain",
    "uri": "url"
  }
}
\`\`\`

For homogeneous feeds, omit the \`type\` field mapping and set \`fixed_type\` instead. Supported output metadata are \`labels\`, \`confidence\`, \`description\`, \`reference\`, \`first_seen\`, \`last_seen\`, \`valid_from\` and \`valid_until\`. After mapping, every record still passes through AEGIS indicator normalization, metadata bounds, exact-match semantics and provenance handling. Unknown configuration keys are rejected. Unsupported or invalid indicator records are skipped.

A configured custom adapter changes the provider ID to \`local-custom-json\`. It remains offline and does not turn external feed fields into attribution, ATT&CK mappings or CVEs.

### STIX 2.1 export

Authenticated operators can export the currently loaded normalized feed indicators as a STIX 2.1 Bundle:

`GET /api/v1/threat-context/stix`

The response uses `application/stix+json` and `Content-Disposition: attachment`. AEGIS maps only supported indicator values and source-supplied metadata. It does not synthesize threat actors, campaigns, ATT&CK techniques or vulnerabilities from a feed match. This export is CTI data, not observed honeypot telemetry.

Every exported indicator is object-marked according to the configured FIRST TLP 2.0 sharing policy (`AEGIS_CTI_EXPORT_TLP`, default `TLP:AMBER+STRICT`). Accepted labels are `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` and `TLP:RED`. Invalid labels fail the export closed. Because STIX 2.1 predates FIRST TLP 2.0, AEGIS uses the mandatory STIX TLP marking compatible with the level plus an explicit statement marking containing the FIRST TLP 2.0 label and sharing boundary. In particular, `TLP:CLEAR` is paired with STIX's standard `TLP:WHITE` marking, and `TLP:AMBER+STRICT` is paired with standard `TLP:AMBER` plus the stricter statement. AEGIS does not create non-standard STIX TLP marking definitions.

FIRST TLP 2.0: https://www.first.org/tlp/
STIX 2.1 data markings: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

Before serialization, the shareable export boundary applies an allowlist and deployment-data sanitizer. IP indicators inside configured sensor management CIDRs are excluded. Configured sensor, ingest and operator secrets are excluded if they appear in indicator values or shareable metadata. Unknown fields — including operator notes or sensor-internal fields — are never copied into the STIX export. Sanitization affects only the shareable export and does not delete historical CTI or honeypot evidence from local storage.

### STIX 2.1 import

`AEGIS_THREAT_CONTEXT_FILE` may also point to a STIX 2.1 Bundle. The local provider imports only exact `indicator` patterns that map to AEGIS-supported IP, domain, URL or file-hash indicator types. Other STIX objects and non-exact/unsupported patterns are ignored rather than interpreted. The same byte/object/resource bounds and exact-match enrichment semantics apply. Imported STIX is read at provider startup; AEGIS does not modify the source bundle.

---

## Italiano

AEGIS-NEXUS può correlare IP osservati e artefatti derivati con un feed JSON locale fornito dall'operatore. L'adapter funziona offline e usa esclusivamente match esatti.

L'adapter JSON locale implementa il contratto comune `ThreatIntelligenceProvider` (`provider_id`, dichiarazione dell'uso rete, `status()`, `enrich()` e `close()` opzionale). Il comportamento offline attuale resta invariato, mentre provider futuri potranno usare lo stesso confine del collector senza introdurre logica di ingestione specifica.

Non effettua **nessuna richiesta di rete** e non invia IP, URL, domini o hash raccolti dall'honeypot a servizi di terze parti.

### Cosa significa un match

Un match indica soltanto che un valore osservato è presente anche nel feed esterno configurato.

Il risultato viene salvato in `enrichment.threat_context` con:
- ID del provider (`local-json`);
- sorgente del feed;
- timestamp di retrieval/caricamento del feed;
- timestamp dell'enrichment;
- `match_policy: exact`;
- timestamp del feed, se disponibile;
- indicatori corrispondenti;
- percorso di evidenza che ha prodotto il candidato, ad esempio `observed.source_ip` o `observed.command`.

Un match **non**:
- aumenta automaticamente la severità;
- crea automaticamente mapping MITRE ATT&CK;
- crea CVE;
- identifica malware family;
- attribuisce l'attività ad actor o campagne;
- dimostra compromissione o intento malevolo.

### Fiducia nel provider e limiti

La Threat Intelligence è contesto esterno, non ground truth. AEGIS registra provenance di provider/sorgente/retrieval per permettere all'analista di valutare origine e anzianità dell'informazione. Label e confidence del feed restano metadata forniti dalla sorgente e non vengono promossi a fatti osservati. I match del provider non possono modificare \`observed\`, creare attribuzione o generare relazioni ATT&CK/CVE. Eventuali provider di rete futuri dovranno dichiarare esplicitamente l'uso della rete e restare indipendenti dagli errori di ingestione della telemetria.

### Tipi supportati

- `ip`
- `domain`
- `url`
- `md5`
- `sha1`
- `sha256`

Domini e hash vengono normalizzati in modo conservativo. Per gli URL vengono normalizzati schema e host, mantenendo path, query e fragment. Record non validi o non supportati vengono ignorati.

### Formato feed

La radice del feed è un oggetto JSON:

```json
{
  "source": "example-local-feed",
  "generated_at": "2026-09-22T20:00:00Z",
  "indicators": [
    {
      "type": "ip",
      "value": "198.51.100.10",
      "labels": ["scanner"],
      "confidence": 70,
      "description": "Record di esempio per documentazione",
      "reference": "https://example.invalid/indicator/1",
      "first_seen": "2026-09-20T00:00:00Z",
      "last_seen": "2026-09-22T00:00:00Z"
    }
  ]
}
```

L'esempio usa esclusivamente dati di documentazione e non viene distribuito come Threat Intelligence reale.

### Contesto scanner benigni

Gli operatori possono montare una lista JSON locale tramite \`AEGIS_BENIGN_SCANNER_FILE\`, con entry come \`{"cidr":"198.51.100.0/24","name":"lab scanner"}\`. Gli IP sorgente corrispondenti ricevono \`enrichment.benign_scanner_context\` con provenance di sorgente/retrieval, \`context_only: true\` e \`suppression: false\`. Il match non modifica la severity, non elimina telemetria, non sopprime detection e non chiude alert. Dimensione file e numero di entry sono bounded.

### Aging e decay degli indicatori

AEGIS conserva invariata la confidence fornita dalla sorgente e deriva separatamente la freschezza. Quando un match dispone di \`last_seen\`, \`first_seen\` o del timestamp \`generated_at\` del feed, il match memorizzato riceve un blocco \`aging\` con timestamp usato come base, \`age_days\`, stato \`fresh\` / \`stale\` / \`aged\` e un \`freshness_score\` deterministico da 100 a 0. I default sono 30 giorni per diventare stale e 90 giorni per diventare aged; sono configurabili con \`AEGIS_CTI_STALE_AFTER_DAYS\` e \`AEGIS_CTI_AGED_AFTER_DAYS\`.

Le validity window della sorgente vengono riportate separatamente come \`active\`, \`not_yet_valid\`, \`expired\` o \`unspecified\`. Un indicatore aged o expired **non viene cancellato né soppresso silenziosamente**: il match storico resta disponibile con evidenza e confidence della sorgente, mentre i metadata di freschezza mostrano all'analista quanto era vecchio il contesto CTI al momento dell'enrichment.

### Limiti sulle risorse

Il loader applica:
- dimensione massima del feed;
- numero massimo di indicatori;
- numero massimo di match per evento;
- limite ai duplicati per indicatore esatto;
- limiti su metadata e label.

Feed malformati o troppo grandi disabilitano in modo sicuro il solo threat-context enrichment: l'ingestione della telemetria continua e lo stato dell'adapter risulta non disponibile.

### Docker Compose

Mantieni il feed fuori da Git:

```bash
mkdir -p threat-context
# Inserisci feed.json in ./threat-context
docker compose -f docker-compose.yml -f docker-compose.threat-context.yml up -d --build
```

La directory viene montata read-only.

Lo stato operatore è disponibile tramite:

`GET /api/v1/threat-context/status`

### Adapter per feed JSON personalizzati

I feed JSON non nativi possono essere mappati nello schema canonico degli indicatori AEGIS senza scrivere codice Python personalizzato. Configura una sola delle seguenti opzioni:

- \`AEGIS_THREAT_CONTEXT_ADAPTER_FILE\` — preferita nei deployment; deve puntare a un file JSON di configurazione montato read-only.
- \`AEGIS_THREAT_CONTEXT_ADAPTER_JSON\` — JSON inline con limite dimensionale, utile per mapping semplici.

L'adapter è esclusivamente dichiarativo: i path con punti attraversano chiavi di oggetti e non sono supportati \`eval\`, JSONPath eseguibile, template o import dinamici di codice. La configurazione è limitata a 16 KiB.

Esempio:

\`\`\`json
{
  "items_path": "data.records",
  "source_path": "meta.vendor",
  "generated_at_path": "meta.created",
  "fields": {
    "type": "indicator.kind",
    "value": "indicator.observable",
    "confidence": "assessment.score",
    "labels": "assessment.tags"
  },
  "type_map": {
    "ipv4": "ip",
    "fqdn": "domain",
    "uri": "url"
  }
}
\`\`\`

Per feed omogenei puoi omettere il mapping del campo \`type\` e usare \`fixed_type\`. I metadata di output supportati sono \`labels\`, \`confidence\`, \`description\`, \`reference\`, \`first_seen\`, \`last_seen\`, \`valid_from\` e \`valid_until\`. Dopo il mapping, ogni record passa comunque attraverso normalizzazione indicatori, limiti metadata, semantica exact-match e provenance di AEGIS. Le chiavi di configurazione sconosciute vengono rifiutate; indicatori non validi o non supportati vengono ignorati.

Con un adapter personalizzato il provider ID diventa \`local-custom-json\`. Il funzionamento resta offline e i campi del feed esterno non vengono trasformati in attribuzione, mapping ATT&CK o CVE.

### Export STIX 2.1

Gli operatori autenticati possono esportare gli indicatori normalizzati del feed attualmente caricato come Bundle STIX 2.1:

`GET /api/v1/threat-context/stix`

La risposta usa `application/stix+json` e `Content-Disposition: attachment`. AEGIS converte esclusivamente indicatori supportati e metadata forniti dalla sorgente. Non genera threat actor, campagne, tecniche ATT&CK o vulnerabilità a partire da un match del feed. L'export contiene dati CTI, non telemetria osservata dall'honeypot.

Ogni indicatore esportato riceve object marking coerenti con la sharing policy FIRST TLP 2.0 configurata (`AEGIS_CTI_EXPORT_TLP`, default `TLP:AMBER+STRICT`). Le label accettate sono `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` e `TLP:RED`; valori non validi fanno fallire l'export in modo chiuso. Poiché STIX 2.1 precede FIRST TLP 2.0, AEGIS usa il marking TLP STIX obbligatorio compatibile con il livello e aggiunge uno statement marking esplicito con label e limite di condivisione FIRST TLP 2.0. In particolare, `TLP:CLEAR` viene associato al marking standard STIX `TLP:WHITE`, mentre `TLP:AMBER+STRICT` usa `TLP:AMBER` più lo statement restrittivo. AEGIS non crea definizioni TLP STIX non standard.

FIRST TLP 2.0: https://www.first.org/tlp/
Data marking STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

Prima della serializzazione, il confine di export condivisibile applica allowlist e sanitizzazione dei dati di deployment. Gli indicatori IP appartenenti ai CIDR management dei sensori configurati vengono esclusi. Secret sensore, ingest e operatore configurati vengono esclusi se compaiono nei valori degli indicatori o nei metadata condivisibili. I campi sconosciuti — incluse note operatore o proprietà interne dei sensori — non vengono mai copiati nell'export STIX. La sanitizzazione riguarda soltanto l'export condivisibile e non cancella CTI storica o evidenze honeypot dallo storage locale.

### Import STIX 2.1

`AEGIS_THREAT_CONTEXT_FILE` può puntare anche a un Bundle STIX 2.1. Il provider locale importa soltanto pattern esatti di tipo `indicator` riconducibili ai tipi IP, dominio, URL o hash di file supportati da AEGIS. Gli altri oggetti STIX e i pattern non esatti/non supportati vengono ignorati, senza interpretarli. Restano validi gli stessi limiti su byte/oggetti/risorse e la stessa semantica di enrichment exact-match. Lo STIX importato viene letto all'avvio del provider; AEGIS non modifica il bundle sorgente.
