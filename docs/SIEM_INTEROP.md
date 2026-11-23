# SIEM interoperability: ECS / OCSF field mapping / Interoperabilità SIEM: mapping ECS / OCSF

## English

This page documents how AEGIS-NEXUS event fields map to the Elastic Common
Schema (ECS) and the Open Cybersecurity Schema Framework (OCSF), for teams that
forward or re-index AEGIS telemetry into a SIEM. It is a **mapping reference**,
not an exporter: AEGIS stores its own evidence-first schema (`schema_version`
in `src/aegis_nexus/model.py`) and any mapping is applied downstream.

### Invariants that survive the mapping

ECS and OCSF are flat "truth" schemas; AEGIS is not. When you project AEGIS onto
them, preserve these properties or the mapping misrepresents the evidence:

- **Keep the four provenance classes.** `observed`, `enrichment`, `derived` and
  `hypotheses` must not collapse into a single field. Carry the original class
  in a namespaced custom field (e.g. `aegis.provenance.class`) alongside the
  mapped value, and never map a `hypotheses` value into a factual ECS/OCSF field.
- **GeoIP/ASN is enrichment, not identity.** `source.geo.*` / `source.as.*` are
  infrastructure context; they do not establish attacker identity or attribution.
- **Never emit cleartext credentials.** AEGIS keeps only a SHA-256 fingerprint
  and length. Map those to custom fields; never synthesize a `user.password`.
- **Captured commands/payloads are attacker input, not executed.** Mapping
  `observed.command` to `process.command_line` is a convenience for search; it
  does not imply execution on the honeypot.
- **MITRE/CVE only when evidence-backed.** Map `derived` MITRE/CVE entries to
  `threat.*` only when they already carry `rationale` + `evidence`.
- **Severity is categorical.** AEGIS uses `info|low|medium|high`; ECS
  `event.severity` is numeric. The mapping below is lossy by design — keep the
  original string in `aegis.severity`.

### ECS field mapping

| AEGIS field | ECS field | Notes |
|---|---|---|
| `id` | `event.id` | AEGIS event UUID |
| `timestamp` | `@timestamp` | sensor-reported event time (analytical axis) |
| `collector.received_at` / `collector_received_at` | `event.ingested` | collector receipt time (drives retention) |
| `event_type` | `event.action` | also set `event.category` per type where known |
| `severity` | `event.severity` + `aegis.severity` | string→numeric is lossy; keep original |
| `honeypot` | `observer.name`, `observer.type: "honeypot"` | the decoy/sensor identity |
| `observed.source_ip` | `source.ip` | |
| `observed.source_port` | `source.port` | |
| `observed.destination_port` | `destination.port` / `server.port` | |
| `observed.protocol` | `network.transport` | tcp/udp |
| `observed.service` | `network.protocol` / `service.name` | application protocol |
| `observed.credential.username` | `user.name` | bounded, hostile input |
| `observed.credential.password_sha256` / `password_length` | `aegis.credential.*` | never `user.password`; no cleartext |
| `observed.command` | `process.command_line` | attacker input, not executed |
| `observed.network.bytes_in` / `bytes_out` | `source.bytes` / `destination.bytes` | when sensor-observed |
| `observed.network.duration` | `event.duration` | |
| `enrichment.geo.country` | `source.geo.country_iso_code` | enrichment, not identity |
| `enrichment.geo.city` | `source.geo.city_name` | |
| `enrichment.geo.latitude` / `longitude` | `source.geo.location` | approximate; carry accuracy radius |
| `enrichment.asn.asn_number` | `source.as.number` | |
| `enrichment.asn.organization` | `source.as.organization.name` | |
| `derived.ioc[]` | `threat.indicator.*` | AEGIS IOC are `observed_artifact`, not TI |
| `derived` MITRE technique | `threat.technique.id` / `threat.tactic.name` | only when evidence-backed |
| `collector.normalization` | `aegis.normalization` | evidence-loss record; keep it |

### OCSF mapping

Map AEGIS events to the OCSF class that matches `event_type`:

- authentication events → **Authentication (3002)**: `src_endpoint.ip`,
  `dst_endpoint.port`, `user.name`, `status`;
- network/connection events → **Network Activity (4001)**:
  `src_endpoint.ip/port`, `dst_endpoint.port`, `connection_info.protocol_num`,
  `traffic.bytes_in/out`;
- detections/alerts → **Detection Finding (2004)**: `finding_info.title`,
  `finding_info.uid` (rule id), `severity_id`, with ATT&CK under
  `finding_info.attacks[]` only when evidence-backed.

Carry AEGIS provenance and normalization in OCSF `unmapped` / `enrichments[]`
so the four evidence classes remain distinguishable after projection.

---

## Italiano

Questa pagina documenta come i campi evento di AEGIS-NEXUS si mappano su Elastic
Common Schema (ECS) e Open Cybersecurity Schema Framework (OCSF), per i team che
inoltrano o re-indicizzano la telemetria AEGIS in un SIEM. È un **riferimento di
mapping**, non un exporter: AEGIS conserva il proprio schema evidence-first
(`schema_version` in `src/aegis_nexus/model.py`) e il mapping si applica a valle.

### Invarianti che sopravvivono al mapping

ECS e OCSF sono schemi piatti di "verità"; AEGIS no. Proiettando AEGIS su di
essi, preserva queste proprietà o il mapping travisa l'evidenza:

- **Mantieni le quattro classi di provenance.** `observed`, `enrichment`,
  `derived` e `hypotheses` non devono collassare in un unico campo. Porta la
  classe originale in un campo custom con namespace (es.
  `aegis.provenance.class`) accanto al valore mappato, e non mappare mai un
  valore `hypotheses` in un campo fattuale ECS/OCSF.
- **GeoIP/ASN è enrichment, non identità.** `source.geo.*` / `source.as.*` sono
  contesto infrastrutturale; non stabiliscono identità o attribuzione.
- **Mai emettere credenziali in chiaro.** AEGIS conserva solo fingerprint
  SHA-256 e lunghezza. Mappali su campi custom; mai sintetizzare `user.password`.
- **Comandi/payload catturati sono input dell'attaccante, non eseguiti.**
  Mappare `observed.command` su `process.command_line` è una comodità di ricerca;
  non implica esecuzione sull'honeypot.
- **MITRE/CVE solo se supportati da evidenza.** Mappa le voci MITRE/CVE di
  `derived` su `threat.*` solo quando portano già `rationale` + `evidence`.
- **La severità è categorica.** AEGIS usa `info|low|medium|high`; ECS
  `event.severity` è numerica. Il mapping è *lossy* per natura — conserva la
  stringa originale in `aegis.severity`.

### Mapping dei campi ECS

| Campo AEGIS | Campo ECS | Note |
|---|---|---|
| `id` | `event.id` | UUID evento AEGIS |
| `timestamp` | `@timestamp` | tempo evento dal sensore (asse analitico) |
| `collector.received_at` / `collector_received_at` | `event.ingested` | tempo di ricezione collector (guida la retention) |
| `event_type` | `event.action` | imposta anche `event.category` per tipo quando noto |
| `severity` | `event.severity` + `aegis.severity` | stringa→numero è lossy; conserva l'originale |
| `honeypot` | `observer.name`, `observer.type: "honeypot"` | identità del decoy/sensore |
| `observed.source_ip` | `source.ip` | |
| `observed.source_port` | `source.port` | |
| `observed.destination_port` | `destination.port` / `server.port` | |
| `observed.protocol` | `network.transport` | tcp/udp |
| `observed.service` | `network.protocol` / `service.name` | protocollo applicativo |
| `observed.credential.username` | `user.name` | input ostile, bounded |
| `observed.credential.password_sha256` / `password_length` | `aegis.credential.*` | mai `user.password`; nessun chiaro |
| `observed.command` | `process.command_line` | input dell'attaccante, non eseguito |
| `observed.network.bytes_in` / `bytes_out` | `source.bytes` / `destination.bytes` | se osservati dal sensore |
| `observed.network.duration` | `event.duration` | |
| `enrichment.geo.country` | `source.geo.country_iso_code` | enrichment, non identità |
| `enrichment.geo.city` | `source.geo.city_name` | |
| `enrichment.geo.latitude` / `longitude` | `source.geo.location` | approssimata; porta il raggio di accuratezza |
| `enrichment.asn.asn_number` | `source.as.number` | |
| `enrichment.asn.organization` | `source.as.organization.name` | |
| `derived.ioc[]` | `threat.indicator.*` | gli IOC AEGIS sono `observed_artifact`, non TI |
| MITRE technique in `derived` | `threat.technique.id` / `threat.tactic.name` | solo se evidence-backed |
| `collector.normalization` | `aegis.normalization` | record di perdita evidenza; conservalo |

### Mapping OCSF

Mappa gli eventi AEGIS sulla classe OCSF che corrisponde a `event_type`:

- eventi di autenticazione → **Authentication (3002)**: `src_endpoint.ip`,
  `dst_endpoint.port`, `user.name`, `status`;
- eventi di rete/connessione → **Network Activity (4001)**:
  `src_endpoint.ip/port`, `dst_endpoint.port`, `connection_info.protocol_num`,
  `traffic.bytes_in/out`;
- detection/alert → **Detection Finding (2004)**: `finding_info.title`,
  `finding_info.uid` (id regola), `severity_id`, con ATT&CK sotto
  `finding_info.attacks[]` solo se evidence-backed.

Porta provenance e normalizzazione AEGIS in `unmapped` / `enrichments[]` di OCSF
così le quattro classi di evidenza restano distinguibili dopo la proiezione.
