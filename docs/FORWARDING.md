# SIEM forwarding / Inoltro verso SIEM

## English

AEGIS-NEXUS can forward events and alerts to an external SIEM. Forwarding is a
**collector-only** outbound data flow: sensors never gain an outbound path
because of it.

### Safety properties

- **Fail-closed.** Forwarding is disabled unless `AEGIS_FORWARDING_ENABLED=true`
  **and** at least one sink is configured. The webhook sink refuses to start
  without a signing secret, so the collector never emits unsigned telemetry, and
  accepts only `http(s)` URLs.
- **Never blocks ingestion.** Records are enqueued without blocking. When the
  bounded queue (`AEGIS_FORWARD_QUEUE_MAX`) is full the record is dropped and
  counted as evidence loss — a slow or unreachable SIEM cannot stall ingest.
- **Bounded delivery.** A single background worker delivers with bounded retries
  (`AEGIS_FORWARD_MAX_RETRIES`); persistent failures are counted, never raised
  into the request path.
- **Provenance preserved.** The forwarded envelope wraps the stored record,
  which keeps its observed/enrichment/derived/hypotheses classes and the
  collector normalization (Evidence Integrity) metadata.
- **Egress still gated.** Enabling forwarding does not bypass perimeter controls:
  the target host must be permitted by the collector egress policy.

### Sinks

- **Syslog (RFC 5424)** over UDP or TCP (`AEGIS_FORWARD_SYSLOG_*`). TCP uses
  RFC 6587 octet-counting framing.
- **Signed JSON webhook** (`AEGIS_FORWARD_WEBHOOK_*`). Each POST carries
  `X-Aegis-Timestamp` and `X-Aegis-Signature` (HMAC-SHA256 over the body, same
  scheme as signed sensor ingest), so the receiver can verify authenticity.

### Privacy

Forwarded payloads may contain personal data (source IPs, usernames). Treat the
SIEM as an extension of the AEGIS trust boundary: apply the same access control
and retention policy, and prefer an internal, authenticated receiver.

---

## Italiano

AEGIS-NEXUS può inoltrare eventi e alert a un SIEM esterno. L'inoltro è un flusso
in uscita **solo del collector**: i sensori non guadagnano alcun percorso in
uscita per via dell'inoltro.

### Proprietà di sicurezza

- **Fail-closed.** L'inoltro è disabilitato se non `AEGIS_FORWARDING_ENABLED=true`
  **e** almeno un sink è configurato. Il sink webhook rifiuta di avviarsi senza
  un segreto di firma, così il collector non emette mai telemetria non firmata, e
  accetta solo URL `http(s)`.
- **Non blocca mai l'ingest.** I record sono accodati senza bloccare. Quando la
  coda limitata (`AEGIS_FORWARD_QUEUE_MAX`) è piena il record viene scartato e
  contato come perdita di evidenza — un SIEM lento o irraggiungibile non può
  fermare l'ingest.
- **Consegna limitata.** Un singolo worker in background consegna con retry
  limitati (`AEGIS_FORWARD_MAX_RETRIES`); i fallimenti persistenti sono contati,
  mai sollevati nel percorso della richiesta.
- **Provenance preservata.** L'envelope inoltrato incapsula il record memorizzato,
  che mantiene le classi observed/enrichment/derived/hypotheses e i metadati di
  normalizzazione del collector (Evidence Integrity).
- **Egress comunque controllato.** Abilitare l'inoltro non aggira i controlli
  perimetrali: l'host di destinazione deve essere permesso dalla policy di egress
  del collector.

### Sink

- **Syslog (RFC 5424)** su UDP o TCP (`AEGIS_FORWARD_SYSLOG_*`). Il TCP usa il
  framing octet-counting di RFC 6587.
- **Webhook JSON firmato** (`AEGIS_FORWARD_WEBHOOK_*`). Ogni POST porta
  `X-Aegis-Timestamp` e `X-Aegis-Signature` (HMAC-SHA256 sul corpo, stesso schema
  dell'ingest firmato dei sensori), così il ricevente può verificarne
  l'autenticità.

### Privacy

I payload inoltrati possono contenere dati personali (IP sorgente, username).
Tratta il SIEM come un'estensione del trust boundary di AEGIS: applica lo stesso
controllo accessi e la stessa policy di retention, e preferisci un ricevente
interno e autenticato.
