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
`sensor_capture`.

The same event also carries the client's `SSH_MSG_KEXINIT` **offer lists** —
`kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms`,
`mac_algorithms`, `compression_algorithms` (client-to-server direction) — and a
`hassh` digest with the `hassh_algorithms` string it was computed from. HASSH is
the Salesforce fingerprint `md5(kex;enc_c2s;mac_c2s;comp_c2s)` (BSD-3-Clause, not
JA4+), useful for clustering attacker SSH tooling regardless of the spoofable
version banner. The offer lists are attacker-influenced, so each list is bounded
(≤ 128 algorithms, each ≤ 64 chars) and the collector re-enforces those bounds
independently; if the lists exceed the caps they are truncated (disclosed under
`sensor_capture`) and `hassh` is omitted, because a digest over truncated lists
would not match any real client. Everything here is strictly a **tooling hint**:
AEGIS never treats the banner, the offer lists or the HASSH as attacker identity,
and never promotes them to an enrichment or derived verdict. See ADR 0005 for
why the JA4+ HTTP/SSH methods are *not* computed natively (licence/patent).

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

Full packet capture (as opposed to this in-app artifact storage) is available as a separate opt-in deployment pattern: per-decoy `tcpdump` sidecars that share each decoy's network namespace and hold `CAP_NET_RAW` while the decoy keeps `cap_drop: ALL`. See `docs/PCAP_CAPTURE.md` and ADR 0005; it is never enabled by default and the collector/decoys gain no raw-socket capability.

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
troncamento è dichiarato sotto `sensor_capture`.

Lo stesso evento riporta anche le **offer-list** del `SSH_MSG_KEXINIT` del client
— `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms`,
`mac_algorithms`, `compression_algorithms` (direzione client→server) — e un
digest `hassh` con la stringa `hassh_algorithms` da cui è calcolato. HASSH è il
fingerprint Salesforce `md5(kex;enc_c2s;mac_c2s;comp_c2s)` (BSD-3-Clause, non
JA4+), utile a raggruppare il tooling SSH dell'attaccante indipendentemente dal
banner di versione (falsificabile). Le offer-list sono influenzate
dall'attaccante, quindi ogni lista è limitata (≤ 128 algoritmi, ciascuno ≤ 64
caratteri) e il collector rimpone gli stessi bound in modo indipendente; se
superano i limiti vengono troncate (dichiarato sotto `sensor_capture`) e `hassh`
viene omesso, perché un digest su liste troncate non corrisponderebbe a nessun
client reale. Tutto qui è solo un **indizio operativo**: AEGIS non tratta mai il
banner, le offer-list o l'HASSH come identità dell'attaccante e non li promuove a
verdetto di enrichment o derived. Vedi ADR 0005 per il motivo per cui i metodi
JA4+ HTTP/SSH *non* sono calcolati nativamente (licenza/brevetto).

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

La cattura full-packet (distinta da questo storage di artefatti in-app) è disponibile come pattern di deployment opt-in separato: sidecar `tcpdump` per-decoy che condividono il netns di ogni decoy e tengono `CAP_NET_RAW` mentre il decoy resta `cap_drop: ALL`. Vedi `docs/PCAP_CAPTURE.md` e l'ADR 0005; non è mai abilitato per default e collector/decoy non acquisiscono capacità raw-socket.

### Privacy e sicurezza

Tutti i metadata network attraversano le stesse regole di normalizzazione hostile-input e bounded storage della restante telemetria. I valori HTTP hanno limiti lato sensore e provenance di troncamento. Un PCAP può contenere payload sensibili, quindi è opt-in, accessibile solo all'operatore, bounded e con retention indipendente. I soli contatori byte/pacchetti non implicano mai conservazione del payload.
