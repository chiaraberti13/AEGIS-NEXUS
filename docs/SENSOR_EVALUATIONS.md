# Sensor expansion evaluations / Valutazioni espansione sensori

This document records design decisions for protocol surfaces that require an explicit safety and evidence review before implementation. An evaluation being complete does **not** mean the protocol is implemented.

Questo documento registra le decisioni di design per superfici di protocollo che richiedono una valutazione esplicita di sicurezza ed evidenza prima dell'implementazione. Una valutazione completata **non** significa che il protocollo sia implementato.

## Decision criteria / Criteri decisionali

Every candidate is reviewed against the same constraints:

- useful telemetry must be obtainable without executing attacker input;
- hostile input must be bounded before parsing or storage;
- authentication material must not be stored in reusable cleartext form;
- the decoy must not expose real shares, desktops, databases, devices or control functions;
- the sensor must fit the existing signed telemetry, heartbeat, isolation and egress model;
- protocol claims must reflect only what the sensor actually observed;
- unsafe or disproportionately complex protocol depth is deferred rather than simulated inaccurately.

Ogni candidato viene valutato con gli stessi vincoli:

- la telemetria utile deve essere ottenibile senza eseguire input dell'attaccante;
- l'input ostile deve essere bounded prima di parsing o storage;
- il materiale di autenticazione non deve essere conservato in forma cleartext riutilizzabile;
- il decoy non deve esporre share, desktop, database, dispositivi o funzioni di controllo reali;
- il sensore deve rispettare il modello esistente di telemetria firmata, heartbeat, isolamento ed egress;
- le affermazioni sul protocollo devono riflettere soltanto ciò che il sensore ha osservato;
- profondità di protocollo non sicure o sproporzionatamente complesse vengono rinviate invece di essere simulate in modo inesatto.

## PostgreSQL

**Decision: accepted for a future bounded decoy. / Decisione: accettato per un futuro decoy bounded.**

Recommended scope:

- accept the PostgreSQL startup framing and protocol 3.0 startup message;
- recognize SSLRequest and answer without creating a real database or TLS identity;
- capture only bounded startup parameters such as requested user, database and application name;
- terminate with a plausible protocol error or authentication failure;
- do not execute SQL, create sessions against a database, proxy traffic or persist password material;
- if authentication challenge emulation is later added, store only non-reusable evidence/fingerprints and document exactly what was observed.

This gives useful scan and client-intent telemetry while keeping the sensor independent from a real PostgreSQL engine.

Scope raccomandato: framing/startup protocol 3.0, riconoscimento SSLRequest, parametri startup bounded e chiusura con errore/autenticazione fallita plausibile. Nessuna esecuzione SQL, nessun database reale, proxy o password persistita.

## RDP

**Decision: accepted only as handshake-level telemetry. / Decisione: accettato solo a livello handshake.**

Recommended scope:

- parse bounded TPKT/X.224 connection requests;
- record requested RDP negotiation protocols/capabilities when present;
- optionally return a minimal negotiation response;
- stop before CredSSP/NLA credential exchange, desktop creation, clipboard, drive mapping or channel emulation;
- never expose a real Windows logon surface.

The value is protocol discovery and scanner/client fingerprint evidence, not interactive desktop emulation.

Il valore è la telemetria di discovery/fingerprint del client, non l'emulazione di un desktop interattivo. CredSSP/NLA, logon, clipboard, drive mapping e canali virtuali restano fuori scope.

## VNC

**Decision: accepted only as bounded RFB negotiation. / Decisione: accettato solo come negoziazione RFB bounded.**

Recommended scope:

- advertise a configurable RFB protocol version;
- capture the bounded client version response;
- expose only a controlled security-type negotiation;
- stop before a usable framebuffer/desktop session;
- do not request or store a reusable VNC password.

This can identify VNC probes without becoming a remote desktop service.

Può identificare probe VNC senza trasformarsi in un servizio desktop remoto. Nessun framebuffer utilizzabile e nessuna password VNC riutilizzabile deve essere acquisita.

## SNMP

**Decision: defer implementation until a dedicated bounded UDP sensor abstraction exists. / Decisione: implementazione rinviata finché non esiste un'astrazione UDP bounded dedicata.**

Reasons:

- current built-in decoys are centered on bounded TCP connection handling;
- SNMP adds UDP datagram handling and ASN.1/BER parsing, which deserves isolated parser limits and fuzz/regression fixtures;
- community strings are authentication-like material and need an explicit privacy representation;
- a fake agent must expose only synthetic read-only OIDs and must never proxy to host/device management data.

A future implementation should be opt-in, read-only and limited to a small synthetic OID tree.

Una futura implementazione dovrà essere opt-in, read-only, con parser BER bounded e un piccolo albero OID sintetico, senza accesso ai dati di gestione dell'host.

## Modbus/TCP ICS

**Decision: defer; lab-only read-only design is required before implementation. / Decisione: rinviato; prima dell'implementazione serve un design read-only e solo laboratorio.**

Reasons:

- an ICS-looking endpoint can attract traffic whose interpretation has operational-safety implications;
- write functions must never affect a real process, PLC, gateway or field device;
- no traffic may be proxied or bridged to OT networks;
- any future decoy must expose synthetic unit/register data only, reject write functions, remain isolated by default and be explicitly enabled by the operator.

The evaluation does not recommend exposing Modbus/TCP on a production or OT network.

La valutazione non raccomanda l'esposizione Modbus/TCP su una rete di produzione o OT. Un eventuale decoy dovrà usare esclusivamente unit/register sintetici, rifiutare le write function ed essere isolato e opt-in.

## Implementation order / Ordine di implementazione

If these candidates are promoted into implementation work, the preferred order is:

1. PostgreSQL bounded startup decoy;
2. RDP handshake-only decoy;
3. VNC negotiation-only decoy;
4. SNMP only after a reusable bounded UDP abstraction and parser tests;
5. Modbus/TCP only as an explicitly enabled lab-only sensor.

The roadmap keeps evaluation and implementation distinct so a completed assessment is never mistaken for a deployed attack surface.

Se questi candidati verranno promossi a implementazione, l'ordine preferito è PostgreSQL, RDP, VNC, quindi SNMP dopo l'astrazione UDP e infine Modbus/TCP esclusivamente come sensore lab opt-in. La roadmap mantiene separati valutazione e implementazione.
