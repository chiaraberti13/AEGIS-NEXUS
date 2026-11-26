# Network evidence / Evidenza di rete

AEGIS-NEXUS stores network-level evidence under `observed.network`. The block is versioned independently from the top-level event schema so network collection can evolve without changing the meaning of older events.

## English

### Schema and provenance

Current schema: `observed.network.schema_version = "1.0"`.

Every network block declares:

- `source`: where the metadata was observed. Current values are `sensor_socket`, `http_request` and `suricata_eve`;
- `capture_layer`: `application`, `transport` or `ids_flow`;
- `completeness`: whether the block is partial or complete for the specific source. AEGIS does not treat missing fields as zero or infer them.

Optional sections are `transport`, `connection`, `http`, `tls`, `dns` and `ssh`. Values remain observed evidence. Deterministic IOC extracted from exact DNS names are stored separately under `derived.ioc` with an evidence path back to `observed.network.dns`.

The `ssh` section carries `client_version`, the SSH client identification string
(e.g. `SSH-2.0-OpenSSH_8.9p1`) observed during the handshake and emitted on a
`connection.identified` event. It is attacker-controlled, so it is bounded to
the 255-byte limit of RFC 4253 §4.2 and any truncation is disclosed under
`sensor_capture`. It is strictly a tooling hint: AEGIS never treats it as
attacker identity and never derives a fingerprint claim from it. Full
KEX/cipher offer lists (HASSH) are not captured — see ADR 0005.

### Collection boundaries

Built-in socket decoys can observe peer/listener ports and connection lifetime. They do not claim packet counters, TCP flags, operating system or packet-level behavior that the application socket cannot directly observe.

The Web decoy records a bounded allow-list of request headers useful for investigation. Authentication and cookie headers are deliberately excluded. `X-Forwarded-For` and `X-Real-IP`, when present, are stored only as untrusted HTTP header evidence and never replace the socket-derived `source_ip`.

Suricata EVE records can provide flow duration, byte/packet counters, transport metadata, HTTP, TLS fingerprints and DNS evidence when those fields are present in the source record. AEGIS preserves only supplied values; it does not synthesize missing counters or fingerprints.

### Passive fingerprints

`PassiveFingerprintProvider` is an optional provider interface over already observed network metadata. Providers must return exact evidence paths. The interface supports TLS/application fingerprints and bounded TCP-stack hints; it deliberately does not expose a direct operating-system attribution kind. Any future hint remains analysis backed by evidence, not an identity or actor claim.

JA4-family fingerprints follow this same rule by licence as well as by design. Per ADR 0005, AEGIS-NEXUS does not compute the FoxIO JA4+ HTTP/SSH methods (JA4H, JA4SSH, …) natively: those are under the non-commercial-only FoxIO License 1.1, which is incompatible with this project's GPLv3 licence, and the methods are patent-pending. Such fingerprints are consumed only as values emitted by an external producer the operator runs (Suricata JA3/JA3S/JA4 passthrough, Zeek), stored as observed evidence. JA4 (TLS) itself is BSD-3-Clause and could be computed natively if ever needed; it is not today because Suricata already supplies it.

### Optional bounded PCAP evidence

PCAP evidence mode is disabled by default. When `AEGIS_PCAP_ENABLED=true`, an authenticated operator can attach a PCAP/PCAPNG artifact to an existing AEGIS session or invoke a configured `PcapCaptureProvider`. The default capture provider is disabled: enabling PCAP storage does not grant the collector `NET_RAW`, `NET_ADMIN` or any packet-sniffing capability.

Every retained artifact has a generated storage name, strict `AEGIS_PCAP_MAX_BYTES` limit, `AEGIS_PCAP_RETENTION_DAYS`, `AEGIS_PCAP_MAX_FILES`, SHA-256 fingerprint and explicit session ID. Downloads verify size and SHA-256 before returning evidence. Original upload filenames are never used as filesystem paths.

### Privacy and safety

All network metadata passes through the same hostile-input normalization and bounded-storage rules as other telemetry. HTTP values are captured with sensor-side limits and truncation provenance. PCAP may contain sensitive payloads, so it is opt-in, operator-only, bounded and independently retained. Byte/packet counters alone never imply payload retention.

---

## Italiano

### Schema e provenienza

Schema corrente: `observed.network.schema_version = "1.0"`.

Ogni blocco network dichiara:

- `source`: dove il metadata è stato osservato. I valori attuali sono `sensor_socket`, `http_request` e `suricata_eve`;
- `capture_layer`: `application`, `transport` oppure `ids_flow`;
- `completeness`: indica se il blocco è parziale o completo per quella specifica sorgente. AEGIS non interpreta i campi mancanti come zero e non li inferisce.

Le sezioni opzionali sono `transport`, `connection`, `http`, `tls`, `dns` e `ssh`. I valori restano evidenza osservata. Gli IOC deterministici estratti da nomi DNS esatti vengono conservati separatamente in `derived.ioc` con evidence path verso `observed.network.dns`.

La sezione `ssh` contiene `client_version`, la stringa di identificazione del
client SSH (es. `SSH-2.0-OpenSSH_8.9p1`) osservata durante l'handshake ed
emessa con un evento `connection.identified`. È controllata dall'attaccante,
quindi viene limitata ai 255 byte previsti dalla RFC 4253 §4.2 e ogni
troncamento è dichiarato sotto `sensor_capture`. È solo un indizio operativo:
AEGIS non la tratta mai come identità dell'attaccante e non ne deriva alcun
fingerprint. Le offer-list complete KEX/cipher (HASSH) non vengono catturate —
vedi ADR 0005.

### Confini della raccolta

I decoy socket built-in possono osservare porte peer/listener e durata della connessione. Non dichiarano packet counter, TCP flag, sistema operativo o comportamento a livello pacchetto che il socket applicativo non può osservare direttamente.

Il Web decoy registra una allow-list bounded di header HTTP utili all'investigazione. Header di autenticazione e cookie sono volutamente esclusi. `X-Forwarded-For` e `X-Real-IP`, quando presenti, vengono conservati soltanto come evidenza HTTP non fidata e non sostituiscono mai il `source_ip` derivato dal socket.

I record Suricata EVE possono fornire durata flow, contatori byte/pacchetti, metadata transport, HTTP, fingerprint TLS ed evidenza DNS quando tali campi sono presenti nel record sorgente. AEGIS conserva esclusivamente valori forniti e non sintetizza contatori o fingerprint mancanti.

### Fingerprint passivi

`PassiveFingerprintProvider` è un'interfaccia opzionale che opera sui metadata di rete già osservati. I provider devono restituire evidence path esatti. L'interfaccia supporta fingerprint TLS/applicativi e hint bounded sullo stack TCP; volutamente non espone un tipo di attribuzione diretta del sistema operativo. Ogni futuro hint resta analisi supportata da evidenza, non una dichiarazione di identità o actor.

I fingerprint della famiglia JA4 seguono questa stessa regola, anche per licenza oltre che per design. Secondo l'ADR 0005, AEGIS-NEXUS non calcola nativamente i metodi FoxIO JA4+ HTTP/SSH (JA4H, JA4SSH, …): sono sotto la FoxIO License 1.1, una licenza solo-non-commerciale incompatibile con la GPLv3 del progetto, e i metodi sono patent-pending. Tali fingerprint vengono consumati solo come valori emessi da un produttore esterno gestito dall'operatore (passthrough Suricata JA3/JA3S/JA4, Zeek), memorizzati come evidenza osservata. JA4 (TLS) è invece BSD-3-Clause e potrebbe essere calcolato nativamente se mai servisse; oggi non lo è perché Suricata lo fornisce già.

### Evidenza PCAP opzionale e bounded

La modalità PCAP è disabilitata per default. Con `AEGIS_PCAP_ENABLED=true`, un operatore autenticato può associare un artefatto PCAP/PCAPNG a una sessione AEGIS esistente oppure invocare un `PcapCaptureProvider` configurato. Il capture provider predefinito è disabilitato: abilitare lo storage PCAP non assegna al collector `NET_RAW`, `NET_ADMIN` o capacità di sniffing.

Ogni artefatto conservato usa un nome storage generato, limite rigido `AEGIS_PCAP_MAX_BYTES`, `AEGIS_PCAP_RETENTION_DAYS`, `AEGIS_PCAP_MAX_FILES`, fingerprint SHA-256 e session ID esplicito. Il download verifica dimensione e SHA-256 prima di restituire l'evidenza. I filename originali dell'upload non vengono mai usati come path filesystem.

### Privacy e sicurezza

Tutti i metadata network attraversano le stesse regole di normalizzazione hostile-input e bounded storage della restante telemetria. I valori HTTP hanno limiti lato sensore e provenance di troncamento. Un PCAP può contenere payload sensibili, quindi è opt-in, accessibile solo all'operatore, bounded e con retention indipendente. I soli contatori byte/pacchetti non implicano mai conservazione del payload.
