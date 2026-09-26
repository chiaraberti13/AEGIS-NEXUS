# Custom sensor development / Sviluppo di sensori custom

This guide defines the minimum contract for adding a third-party or deployment-specific decoy to AEGIS-NEXUS without weakening the collector trust boundary.

Questa guida definisce il contratto minimo per aggiungere un decoy third-party o specifico del deployment ad AEGIS-NEXUS senza indebolire il trust boundary del collector.

## 1. Safety contract / Contratto di sicurezza

A sensor is an **emulator**, not a command runner, proxy or sandbox.

Every sensor must:

- declare `executes_attacker_input=False`;
- never call shells, interpreters or OS execution primitives with remote input;
- bound input before parsing, hashing or emitting telemetry;
- reject or explicitly mark truncation instead of silently changing evidence semantics;
- avoid real authentication, writable production resources and attacker-controlled outbound connections;
- send telemetry only through `SensorClient` using its dedicated sensor identity and secret;
- run with a read-only root filesystem, dropped capabilities and `no-new-privileges`;
- use dedicated exposure and management networks;
- be covered by both IPv4 and IPv6 egress controls before Internet exposure.

Un sensore è un **emulatore**, non un command runner, proxy o sandbox. L'input remoto non deve mai raggiungere primitive di esecuzione, risorse reali o connessioni outbound controllate dall'attaccante.

## 2. Plugin contract / Contratto plugin

A plugin exposes a stable name, truthful capabilities, bounded configuration and a run method:

```python
from aegis_nexus.sensors.base import SensorCapabilities, SensorConfig
from aegis_nexus.sensors.registry import register_sensor

@register_sensor
class ExampleSensorPlugin:
    name = "example"
    capabilities = SensorCapabilities(
        protocols=("example", "tcp"),
        event_types=("connection", "example.request", "sensor.input_rejected"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
        captures_credentials=False,
        captures_commands=False,
        captures_payloads=False,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id="example-decoy-01",
            enabled=True,
            bind_host="::",
            ports={"example": 9001},
            options={"max_connections": 32},
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        ...
```

Do not declare capabilities that the sensor cannot actually observe. A protocol fingerprint, banner or client hint is evidence about tooling/traffic, never an identity or attribution claim.

Non dichiarare capability che il sensore non può realmente osservare. Fingerprint, banner e client hint non equivalgono a identità o attribuzione.

## 3. Hostile-input handling / Gestione input ostile

Choose explicit protocol limits: frame size, line size, collection count, nesting depth and connection timeout. Reject oversized framing before reading an unbounded body whenever the protocol allows it.

When a bounded representation loses information, attach `observed.sensor_capture` metadata through the existing capture helpers. Secrets and opaque authentication blobs should normally be represented by length + SHA-256 rather than reusable cleartext.

For uploaded files, use `SensorClient.quarantine_artifact()`; never persist them in the exposed sensor container. Quarantine is evidence storage, not malware execution.

Definisci limiti espliciti per frame, linee, collezioni, profondità e timeout. Se la rappresentazione perde informazione, dichiaralo nei metadata `sensor_capture`. Per gli upload usa esclusivamente la quarantena del collector.

## 4. Evidence model / Modello delle evidenze

Keep the existing separation:

- **Observed:** directly captured protocol/socket facts.
- **Enrichment:** external/context data with source provenance.
- **Derived:** deterministic transformations backed by evidence.
- **Hypotheses:** analyst/research interpretations, never presented as observed fact.

Use `make_network_evidence()` for transport/connection evidence and include the actual listener destination port. Source addresses are normalized by the collector; dual-stack listeners should bind to `::` when the platform/deployment supports IPv6.

Mantieni separate evidenze osservate, enrichment, derived e hypotheses. La telemetria di rete deve usare lo schema versionato esistente.

## 5. Authentication and trust boundary / Autenticazione e trust boundary

Each deployed sensor needs:

1. a unique `AEGIS_SENSOR_API_KEY`;
2. an explicit sensor ID in the collector `AEGIS_SENSOR_KEYS` allowlist;
3. a dedicated internal management subnet in `AEGIS_SENSOR_SOURCE_CIDRS`;
4. signed telemetry (default);
5. a dedicated exposure network;
6. no access from its management subnet to operator/UI APIs.

Do not reuse another built-in sensor identity or secret.

Ogni sensore deve avere identità, secret, management subnet ed exposure network dedicati. Non riutilizzare l'identità di un altro decoy.

## 6. Docker and egress checklist / Checklist Docker ed egress

Before enabling a custom sensor:

- non-root image user;
- `read_only: true`;
- `cap_drop: ["ALL"]`;
- `no-new-privileges:true`;
- bounded PID/CPU/memory/file-descriptor limits;
- bounded temporary filesystem with `noexec,nosuid,nodev`;
- only required published ports;
- dedicated dual-stack exposure CIDRs when IPv6 is enabled;
- dedicated internal management network;
- exposure CIDRs included in the host egress guard or equivalent external firewall policy;
- verify inbound replies still work and **new outbound IPv4 and IPv6 connections fail**.

A custom deployment that cannot provide equivalent egress containment should not expose the decoy directly to the Internet.

## 7. Required tests / Test obbligatori

A sensor is not ready until tests cover:

- normal protocol negotiation/emulation;
- malformed and oversized hostile input;
- secret/payload non-retention where applicable;
- `executes_attacker_input=False`;
- absence of execution primitives;
- IPv4/IPv6 listener configuration;
- dedicated Compose isolation;
- egress-guard coverage;
- telemetry normalization and provenance;
- authentication/source-CIDR rejection;
- IT/EN documentation for operator-visible behavior.

Add the module to the protocol-module list in `tests/test_sensor_safety.py` so static execution-primitive checks cannot silently omit it. Extend `scripts/verify_compose_isolation.py` for Compose-managed sensors.

Un sensore non è pronto finché i test non coprono protocollo normale, input ostile, privacy dei secret/payload, assenza di esecuzione, dual-stack, isolamento, egress, provenance e autenticazione.

## 8. Registration / Registrazione

Built-in sensors are explicitly loaded in `aegis_nexus.sensors.catalog`. Add a new built-in there only after its tests pass. External deployment-specific plugins may use the same interface, but should not modify the collector event schema merely to encode protocol-specific fields: keep protocol evidence under bounded `observed` structures and evolve shared schemas deliberately.

I sensori built-in vengono caricati esplicitamente dal catalogo. I plugin esterni possono usare la stessa interfaccia, ma non devono alterare ad hoc lo schema eventi del collector.

## 9. Review gate / Gate di revisione

Before marking a roadmap sensor task complete, require a green CI run for the exact head containing the implementation and documentation. If a protocol needs real command execution, unrestricted filesystem access, real credentials, uncontrolled packet capture or outbound callbacks to behave convincingly, reduce the emulation scope instead of weakening the safety boundary.

Prima di completare un task della roadmap, la CI dell'head esatto deve essere verde. Se un protocollo richiede esecuzione reale o accessi non controllati, riduci lo scope dell'emulazione invece di indebolire il confine di sicurezza.
