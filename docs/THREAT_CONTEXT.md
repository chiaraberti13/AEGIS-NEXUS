# Local threat context / Threat context locale

## English

AEGIS-NEXUS can correlate observed IPs and derived artifacts against an operator-supplied local JSON feed. The adapter is offline and exact-match only.

It performs **no network requests** and never sends honeypot IPs, URLs, domains or hashes to a third-party service.

### What a match means

A match means only that an exact observed value also exists in the configured external feed.

The result is stored in `enrichment.threat_context` with:
- the feed source;
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

---

## Italiano

AEGIS-NEXUS può correlare IP osservati e artefatti derivati con un feed JSON locale fornito dall'operatore. L'adapter funziona offline e usa esclusivamente match esatti.

Non effettua **nessuna richiesta di rete** e non invia IP, URL, domini o hash raccolti dall'honeypot a servizi di terze parti.

### Cosa significa un match

Un match indica soltanto che un valore osservato è presente anche nel feed esterno configurato.

Il risultato viene salvato in `enrichment.threat_context` con:
- sorgente del feed;
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
