# Network evidence / Evidenza di rete

AEGIS-NEXUS stores network-level evidence under `observed.network`. The block is versioned independently from the top-level event schema so network collection can evolve without changing the meaning of older events.

## English

### Schema and provenance

Current schema: `observed.network.schema_version = "1.0"`.

Every network block declares:

- `source`: where the metadata was observed. Current values are `sensor_socket`, `http_request` and `suricata_eve`;
- `capture_layer`: `application`, `transport` or `ids_flow`;
- `completeness`: whether the block is partial or complete for the specific source. AEGIS does not treat missing fields as zero or infer them.

Optional sections are `transport`, `connection`, `http`, `tls` and `dns`. Values remain observed evidence. Deterministic IOC extracted from exact DNS names are stored separately under `derived.ioc` with an evidence path back to `observed.network.dns`.

### Collection boundaries

Built-in socket decoys can observe peer/listener ports and connection lifetime. They do not claim packet counters, TCP flags, operating system or packet-level behavior that the application socket cannot directly observe.

The Web decoy records a bounded allow-list of request headers useful for investigation. Authentication and cookie headers are deliberately excluded. `X-Forwarded-For` and `X-Real-IP`, when present, are stored only as untrusted HTTP header evidence and never replace the socket-derived `source_ip`.

Suricata EVE records can provide flow duration, byte/packet counters, transport metadata, HTTP, TLS fingerprints and DNS evidence when those fields are present in the source record. AEGIS preserves only supplied values; it does not synthesize missing counters or fingerprints.

### Passive fingerprints

`PassiveFingerprintProvider` is an optional provider interface over already observed network metadata. Providers must return exact evidence paths. The interface supports TLS/application fingerprints and bounded TCP-stack hints; it deliberately does not expose a direct operating-system attribution kind. Any future hint remains analysis backed by evidence, not an identity or actor claim.

### Privacy and safety

All network metadata passes through the same hostile-input normalization and bounded-storage rules as other telemetry. HTTP values are captured with sensor-side limits and truncation provenance. Packet capture is not enabled by this schema and no payload retention is implied by byte/packet counters.

---

## Italiano

### Schema e provenienza

Schema corrente: `observed.network.schema_version = "1.0"`.

Ogni blocco network dichiara:

- `source`: dove il metadata è stato osservato. I valori attuali sono `sensor_socket`, `http_request` e `suricata_eve`;
- `capture_layer`: `application`, `transport` oppure `ids_flow`;
- `completeness`: indica se il blocco è parziale o completo per quella specifica sorgente. AEGIS non interpreta i campi mancanti come zero e non li inferisce.

Le sezioni opzionali sono `transport`, `connection`, `http`, `tls` e `dns`. I valori restano evidenza osservata. Gli IOC deterministici estratti da nomi DNS esatti vengono conservati separatamente in `derived.ioc` con evidence path verso `observed.network.dns`.

### Confini della raccolta

I decoy socket built-in possono osservare porte peer/listener e durata della connessione. Non dichiarano packet counter, TCP flag, sistema operativo o comportamento a livello pacchetto che il socket applicativo non può osservare direttamente.

Il Web decoy registra una allow-list bounded di header HTTP utili all'investigazione. Header di autenticazione e cookie sono volutamente esclusi. `X-Forwarded-For` e `X-Real-IP`, quando presenti, vengono conservati soltanto come evidenza HTTP non fidata e non sostituiscono mai il `source_ip` derivato dal socket.

I record Suricata EVE possono fornire durata flow, contatori byte/pacchetti, metadata transport, HTTP, fingerprint TLS ed evidenza DNS quando tali campi sono presenti nel record sorgente. AEGIS conserva esclusivamente valori forniti e non sintetizza contatori o fingerprint mancanti.

### Fingerprint passivi

`PassiveFingerprintProvider` è un'interfaccia opzionale che opera sui metadata di rete già osservati. I provider devono restituire evidence path esatti. L'interfaccia supporta fingerprint TLS/applicativi e hint bounded sullo stack TCP; volutamente non espone un tipo di attribuzione diretta del sistema operativo. Ogni futuro hint resta analisi supportata da evidenza, non una dichiarazione di identità o actor.

### Privacy e sicurezza

Tutti i metadata network attraversano le stesse regole di normalizzazione hostile-input e bounded storage della restante telemetria. I valori HTTP hanno limiti lato sensore e provenance di troncamento. Lo schema non abilita packet capture e i contatori byte/pacchetti non implicano conservazione del payload.
