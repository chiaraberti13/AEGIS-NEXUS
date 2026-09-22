# Sensor isolation / Isolamento dei sensori

## English

The honeypot services are deliberately low/intermediate interaction. Captured commands and payloads are **never executed**. The SSH sensor emulates a small command set in memory, the web sensor returns fabricated responses without filesystem access, and FTP/Telnet listeners use bounded line readers.

Docker Compose separates two purposes:

- `aegis_dmz`: network used by externally exposed decoys.
- `aegis_mgmt`: internal telemetry network used to reach the collector.

The collector is not published to the Internet; its operator/API port is bound to `127.0.0.1:8600`. Decoys receive resource caps, run as the non-root image user, use a read-only root filesystem, drop all Linux capabilities and enable `no-new-privileges`.

A sensor necessarily has a narrow telemetry path to the collector. This is not equivalent to full one-way hardware isolation. For Internet-facing research, place the Docker host in a dedicated VLAN/VM, deny access to production subnets, restrict outbound traffic at the firewall, monitor the host itself and rotate the ingest secret regularly.

The default public ports are intentionally high ports (2222, 8080, 2121, 2323). If you map them to 22/80/21/23 with host firewall/NAT rules, document that change and do not grant extra container capabilities merely to bind privileged ports.

## Italiano

I servizi honeypot sono volutamente a bassa/intermedia interazione. Comandi e payload catturati **non vengono mai eseguiti**. Il sensore SSH emula in memoria un piccolo insieme di comandi, il sensore web restituisce risposte fittizie senza accedere al filesystem e i listener FTP/Telnet usano letture con limiti rigidi.

Docker Compose separa due funzioni:

- `aegis_dmz`: rete dei servizi esca esposti.
- `aegis_mgmt`: rete interna usata esclusivamente per la telemetria verso il collector.

Il collector non viene pubblicato su Internet; la console/API operatore resta su `127.0.0.1:8600`. I decoy hanno limiti di risorse, girano con utente non-root, root filesystem in sola lettura, nessuna capability Linux e `no-new-privileges`.

Il sensore mantiene necessariamente un percorso ristretto di telemetria verso il collector: non equivale a un isolamento hardware unidirezionale. Per esposizioni Internet usa una VLAN/VM dedicata, blocca le subnet di produzione, limita l'egress via firewall, monitora anche l'host e ruota periodicamente il secret di ingestione.

Le porte pubbliche predefinite sono volutamente alte (2222, 8080, 2121, 2323). Se le rimappi a 22/80/21/23 tramite firewall/NAT dell'host, documenta la modifica e non aggiungere capability ai container solo per usare porte privilegiate.
