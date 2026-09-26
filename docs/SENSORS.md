# Sensor plugins / Plugin sensori

AEGIS built-in decoys implement the common interface in `aegis_nexus.sensors.base` and are discoverable through `SensorRegistry`.

## English

A sensor plugin declares a stable `name`, `SensorCapabilities`, `config_from_env()` and `run(config)`. `SensorConfig` keeps identity, enable/disable state, bind host, protocol ports and bounded options separate from protocol logic.

Capability metadata is evidence-oriented: protocols, emitted event types, interaction mode, network-evidence sections and whether the sensor captures credentials, commands or payloads. `executes_attacker_input=True` is rejected by the registry.

Built-in plugins are loaded explicitly through `load_builtin_sensors()`. This avoids importing protocol runtimes in the collector process merely to inspect the catalog.

To add a custom sensor:

1. implement the common plugin interface;
2. declare truthful capabilities and keep `executes_attacker_input=False`;
3. use `SensorClient` for authenticated/signed telemetry;
4. bound hostile input before emission and attach `sensor_capture` metadata when truncation/rejection occurs;
5. emit network metadata through the versioned `observed.network` schema when available;
6. use a dedicated exposure network, management network, sensor secret and source-CIDR binding;
7. add the exposure CIDR to the host egress guard;
8. add protocol, hostile-input, isolation and Compose/CI tests before enabling the sensor.

A custom sensor must emulate an attack surface; it must not execute commands, payloads, uploaded code or authentication material supplied by a remote client.

For the complete plugin contract, containment checklist, evidence rules and required test gate, see [`CUSTOM_SENSORS.md`](CUSTOM_SENSORS.md).

### Deployment personas

Built-in decoys load one bounded operator-controlled persona from `AEGIS_DECOY_PERSONA_JSON` or, for direct deployments, `AEGIS_DECOY_PERSONA_FILE`. A persona can change hostname, emulated username, Web title/heading, SMTP/FTP/Telnet banners, Redis/MySQL version strings and the SSH fake filesystem without changing collector logic. Persona files are limited to 64 KiB; fake files are limited in count and size, absolute paths only, and traversal paths are rejected. Protocol identity fields strip CR/LF/NUL characters before use.

Default protocol identity is selected from bounded plausible profiles and varied with `AEGIS_DECOY_PERSONA_SEED` (or a process-local fallback) so separate deployments do not all expose one identical static fingerprint. Regression tests reject obvious decoy-product markers such as `aegis`, `honeypot`, `cowrie` and `kippo` in default protocol identity. This reduces trivial fingerprinting; it does not claim that a decoy is indistinguishable from a production service.

Personas are presentation only. They do not enable command execution, create real accounts or expose a writable filesystem. Do not place real credentials, secrets or sensitive production content in a persona.

### Generic TCP banner sensor

The `generic-tcp` plugin is a banner-only, opt-in surface for ports that do not justify a protocol-specific emulator. Compose keeps it behind the `generic` profile. Configure a dedicated `AEGIS_GENERIC_SENSOR_API_KEY`, `AEGIS_GENERIC_TCP_BANNER` and public port before enabling it. The banner is bounded and CR/LF/NUL injection is normalized. Client probe content is not stored; telemetry retains only captured length and SHA-256. The sensor has dedicated exposure/management networks and is covered by the host egress guard.

### Honeytoken credentials

Honeytokens are disabled unless `AEGIS_HONEYTOKEN_SEED` is configured. When enabled, AEGIS derives one deployment-specific synthetic backup credential and plants it in the SSH fake filesystem. The collector derives the same expected username and password fingerprint from the seed. If normalized credential telemetry later contains both values, the Detection Engine emits `honeytoken_reuse` with high severity and 100 confidence. The alert contains evidence references, not the planted password or its fingerprint, and makes no actor-attribution claim.

Use a random deployment-specific seed and treat it as configuration secret material. Honeytokens must never reuse a real username/password or production secret.

### Hostile artifact uploads

Web uploads and FTP `STOR` are forwarded to the collector quarantine instead of being written inside exposed sensor containers. FTP uses EPSV passive transfer only; active `PORT` mode is disabled. The current SSH decoy does not emulate SCP/SFTP. Size/count limits, SHA-256 handling and the no-inline-serving rule are defined in `docs/QUARANTINE.md`.

## Italiano

I decoy built-in di AEGIS implementano l'interfaccia comune in `aegis_nexus.sensors.base` e sono registrabili tramite `SensorRegistry`.

Un plugin sensore dichiara `name`, `SensorCapabilities`, `config_from_env()` e `run(config)`. `SensorConfig` separa identità, stato enabled, bind host, porte di protocollo e opzioni bounded dalla logica del protocollo.

I capability metadata descrivono protocolli, event type emessi, interaction mode, sezioni di network evidence e se il sensore cattura credential, comandi o payload. Il registry rifiuta `executes_attacker_input=True`.

I plugin built-in vengono caricati esplicitamente tramite `load_builtin_sensors()`, evitando di importare runtime di protocollo nel collector soltanto per consultare il catalogo.

Per aggiungere un sensore custom:

1. implementa l'interfaccia plugin comune;
2. dichiara capability reali e mantieni `executes_attacker_input=False`;
3. usa `SensorClient` per telemetria autenticata e firmata;
4. applica limiti all'input ostile prima dell'invio e aggiungi `sensor_capture` quando avvengono troncamenti/rifiuti;
5. usa lo schema versionato `observed.network` per i metadata di rete disponibili;
6. assegna exposure network, management network, secret e source-CIDR binding dedicati;
7. aggiungi la subnet exposure all'egress guard host;
8. aggiungi test di protocollo, hostile-input, isolamento e Compose/CI prima di abilitare il sensore.

Un sensore custom deve emulare una superficie di attacco; non deve eseguire comandi, payload, codice caricato o materiale di autenticazione fornito da un client remoto.

Per contratto plugin completo, checklist di contenimento, regole sulle evidenze e test gate obbligatorio, consulta [`CUSTOM_SENSORS.md`](CUSTOM_SENSORS.md).

### Persona di deployment

I decoy built-in caricano una persona bounded controllata dall'operatore tramite `AEGIS_DECOY_PERSONA_JSON` oppure, nei deployment diretti, `AEGIS_DECOY_PERSONA_FILE`. La persona può cambiare hostname, username emulato, titolo/intestazione Web, banner SMTP/FTP/Telnet, versioni Redis/MySQL e fake filesystem SSH senza modificare il collector. Il file persona è limitato a 64 KiB; i fake file hanno limiti di numero e dimensione, accettano solo path assoluti e rifiutano traversal. I campi usati nei protocolli rimuovono CR/LF/NUL prima dell'uso.

L'identità di protocollo predefinita viene scelta tra profili plausibili e bounded e variata tramite `AEGIS_DECOY_PERSONA_SEED` (o un fallback locale al processo), così deployment differenti non espongono tutti lo stesso fingerprint statico. I test di regressione rifiutano marker evidenti di prodotti decoy come `aegis`, `honeypot`, `cowrie` e `kippo` nell'identità predefinita. Questo riduce il fingerprinting banale; non implica che un decoy sia indistinguibile da un servizio di produzione.

Le persona modificano soltanto la presentazione. Non abilitano esecuzione di comandi, non creano account reali e non espongono un filesystem scrivibile. Non inserire credenziali reali, secret o contenuti sensibili di produzione.

### Sensore banner TCP generico

Il plugin `generic-tcp` è una superficie banner-only e opt-in per porte che non richiedono un emulatore di protocollo specifico. Compose lo mantiene dietro il profilo `generic`. Prima di abilitarlo configura `AEGIS_GENERIC_SENSOR_API_KEY`, `AEGIS_GENERIC_TCP_BANNER` e la porta pubblica dedicata. Il banner è bounded e normalizza injection CR/LF/NUL. Il contenuto del probe client non viene conservato: la telemetria mantiene soltanto lunghezza catturata e SHA-256. Il sensore usa reti exposure/management dedicate ed è incluso nell'egress guard host.

### Credenziali honeytoken

Gli honeytoken sono disabilitati finché non viene configurato `AEGIS_HONEYTOKEN_SEED`. Quando attivi, AEGIS deriva una credenziale sintetica di backup specifica del deployment e la inserisce nel fake filesystem SSH. Il collector deriva dallo stesso seed username e fingerprint attesi. Se la telemetria credential normalizzata contiene successivamente entrambi i valori, il Detection Engine genera `honeytoken_reuse` con severity high e confidence 100. L'alert contiene riferimenti alle evidenze, non la password piantata né il suo fingerprint, e non formula attribuzioni sull'attore.

Usa un seed casuale specifico del deployment e trattalo come materiale di configurazione segreto. Gli honeytoken non devono mai riutilizzare username/password reali o secret di produzione.

### Upload di artefatti ostili

Gli upload Web e FTP `STOR` vengono inoltrati alla quarantena del collector invece di essere scritti nei container sensore esposti. FTP usa esclusivamente trasferimento passivo EPSV; la modalità active `PORT` è disabilitata. Il decoy SSH attuale non emula SCP/SFTP. Limiti di dimensione/numero, gestione SHA-256 e regola di non-inline-serving sono definiti in `docs/QUARANTINE.md`.
