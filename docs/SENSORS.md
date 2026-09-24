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

### Deployment personas

Built-in decoys load one bounded operator-controlled persona from `AEGIS_DECOY_PERSONA_JSON` or, for direct deployments, `AEGIS_DECOY_PERSONA_FILE`. A persona can change hostname, emulated username, Web title/heading, SMTP/FTP/Telnet banners, Redis/MySQL version strings and the SSH fake filesystem without changing collector logic. Persona files are limited to 64 KiB; fake files are limited in count and size, absolute paths only, and traversal paths are rejected. Protocol identity fields strip CR/LF/NUL characters before use.

Personas are presentation only. They do not enable command execution, create real accounts or expose a writable filesystem. Do not place real credentials, secrets or sensitive production content in a persona.

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

### Persona di deployment

I decoy built-in caricano una persona bounded controllata dall'operatore tramite `AEGIS_DECOY_PERSONA_JSON` oppure, nei deployment diretti, `AEGIS_DECOY_PERSONA_FILE`. La persona può cambiare hostname, username emulato, titolo/intestazione Web, banner SMTP/FTP/Telnet, versioni Redis/MySQL e fake filesystem SSH senza modificare il collector. Il file persona è limitato a 64 KiB; i fake file hanno limiti di numero e dimensione, accettano solo path assoluti e rifiutano traversal. I campi usati nei protocolli rimuovono CR/LF/NUL prima dell'uso.

Le persona modificano soltanto la presentazione. Non abilitano esecuzione di comandi, non creano account reali e non espongono un filesystem scrivibile. Non inserire credenziali reali, secret o contenuti sensibili di produzione.
