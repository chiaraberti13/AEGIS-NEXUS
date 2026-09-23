# Sensor isolation / Isolamento dei sensori

## English

AEGIS-NEXUS uses deliberately low/intermediate-interaction decoys. Captured commands and payloads are **recorded or emulated, never executed**. The SSH sensor implements a small in-memory command emulator, the web sensor returns fabricated responses without attacker-directed filesystem access, and FTP/Telnet listeners use bounded readers.

### Docker network model

Each sensor now has two dedicated networks:

- an exposure network used only by that sensor for its published host port;
- an internal management network shared only with the collector.

This means the SSH, web and legacy sensors do not share a management network and are not intended to communicate laterally with one another. The collector joins the three internal management networks but is published only on `127.0.0.1:8600`.

The Compose topology is:

`ssh_exposure → ssh-decoy → ssh_mgmt → collector`

`web_exposure → web-decoy → web_mgmt → collector`

`legacy_exposure → legacy-decoy → legacy_mgmt → collector`

The telemetry path is narrow but it is not a hardware data diode. The three exposure networks are ordinary bridge networks because published honeypot ports must remain reachable. Their CIDRs are explicitly configured through `AEGIS_SSH_EXPOSURE_SUBNET`, `AEGIS_WEB_EXPOSURE_SUBNET` and `AEGIS_LEGACY_EXPOSURE_SUBNET`.

For a Linux Docker host, AEGIS includes an idempotent host-side egress guard. Run `sudo make egress-guard` after Docker is running and before Internet exposure. It installs a dedicated `AEGIS_NEXUS_EGRESS` chain reached from Docker's `DOCKER-USER` chain. For each sensor exposure CIDR it permits `ESTABLISHED,RELATED` reply traffic and drops new traffic initiated from the decoy exposure interface. Check the active rules with `sudo make egress-status`; remove only during maintenance with `sudo make egress-remove`.

The guard intentionally does not modify container capabilities or execute inside a decoy. It preserves the published inbound ports and the original remote source address while reducing pivot risk. The configured CIDRs must not overlap host, LAN, VPN or production networks. Treat an absent guard as a degraded isolation state for Internet-facing deployment, and verify both inbound honeypot reachability and denied new outbound connections after every Docker/firewall upgrade.

Do not assume that changing a published sensor's exposure network to Compose `internal: true` is a drop-in replacement. Internal-only bridge networking can affect port publishing on recent Docker releases. AEGIS therefore keeps management networks internal and enforces sensor egress at the host forwarding boundary.

### Sensor identity isolation

The standard Compose deployment assigns distinct ingest secrets to SSH, web and legacy decoys. The collector receives these through `AEGIS_SENSOR_KEYS`, which acts as an allowlist: when the map is configured, the shared `AEGIS_INGEST_API_KEY` is not accepted as a fallback and unknown sensor IDs are rejected. Signed requests therefore authenticate both payload integrity and the expected sensor identity.

The built-in Compose sensors are additionally source-bound through `AEGIS_SENSOR_SOURCE_CIDRS` to explicit `ssh_mgmt`, `web_mgmt` and `legacy_mgmt` CIDRs. A valid sensor key presented from the wrong management subnet is rejected. Requests that originate from any configured sensor-management CIDR are also denied access to the dashboard, static UI, operator status and other operator APIs; only the two ingestion endpoints are reachable from those trust zones. This is a defense-in-depth control for a compromised decoy and does not replace key rotation or network isolation.

Suricata uses the optional `AEGIS_SURICATA_SENSOR_API_KEY` and is intentionally not source-bound by the default Compose mapping because the included forwarder runs on the host. Custom sensors must be added explicitly to the collector allowlist and, when appropriate, to `AEGIS_SENSOR_SOURCE_CIDRS`. Rotate one sensor key independently after suspected compromise instead of rotating every decoy at once.

### Runtime containment

Sensors run as the non-root image user with:

- read-only root filesystems;
- all Linux capabilities dropped;
- `no-new-privileges`;
- PID, CPU, memory and file-descriptor limits;
- bounded concurrent TCP connections through `AEGIS_SENSOR_MAX_CONNECTIONS`;
- application-level timeouts and bounded input readers.

The web and collector Gunicorn processes also limit request line/header sizes, keep-alive duration and requests per worker.

For Internet-facing research, place the Docker host in a dedicated VLAN/VM, deny routes to production subnets, restrict egress at the host/network firewall, monitor the host itself and rotate ingest credentials regularly. Do not mount Docker sockets, host directories or sensitive credentials into sensor containers.

The default public ports are intentionally high ports (2222, 8080, 2121, 2323). If you map them to 22/80/21/23 with host firewall/NAT rules, document that change and do not grant extra container capabilities merely to bind privileged ports.

---

## Italiano

AEGIS-NEXUS utilizza decoy volutamente a bassa/intermedia interazione. Comandi e payload catturati vengono **registrati o emulati, mai eseguiti**. Il sensore SSH implementa un piccolo emulatore di comandi in memoria, il sensore web restituisce risposte fittizie senza accesso al filesystem controllato dall'attaccante e i listener FTP/Telnet utilizzano letture con limiti rigidi.

### Modello di rete Docker

Ogni sensore dispone ora di due reti dedicate:

- una rete di esposizione utilizzata solo da quel sensore per la porta pubblicata sull'host;
- una rete management interna condivisa esclusivamente con il collector.

SSH, web e legacy non condividono quindi una rete management e non sono progettati per comunicare lateralmente tra loro. Il collector è collegato alle tre reti management interne ma viene pubblicato soltanto su `127.0.0.1:8600`.

La topologia Compose è:

`ssh_exposure → ssh-decoy → ssh_mgmt → collector`

`web_exposure → web-decoy → web_mgmt → collector`

`legacy_exposure → legacy-decoy → legacy_mgmt → collector`

Il percorso di telemetria è ristretto ma non equivale a un data diode hardware. Le tre reti di esposizione restano normali bridge Docker perché le porte pubblicate degli honeypot devono rimanere raggiungibili. Le relative CIDR sono configurate esplicitamente tramite `AEGIS_SSH_EXPOSURE_SUBNET`, `AEGIS_WEB_EXPOSURE_SUBNET` e `AEGIS_LEGACY_EXPOSURE_SUBNET`.

Su un host Docker Linux AEGIS include ora un egress guard host-side idempotente. Esegui `sudo make egress-guard` dopo l'avvio di Docker e prima dell'esposizione a Internet. Lo script installa una chain dedicata `AEGIS_NEXUS_EGRESS` richiamata da `DOCKER-USER`: per ogni CIDR di esposizione consente il traffico di risposta `ESTABLISHED,RELATED` e blocca le nuove connessioni originate dall'interfaccia di esposizione del decoy. Verifica le regole con `sudo make egress-status`; rimuovile soltanto durante manutenzione con `sudo make egress-remove`.

Il guard non aggiunge capability ai container e non viene eseguito dentro i decoy. Mantiene le porte inbound pubblicate e l'indirizzo sorgente remoto originale, riducendo il rischio di pivot. Le CIDR configurate non devono sovrapporsi a reti host, LAN, VPN o produzione. Per un deployment Internet-facing considera l'assenza del guard come isolamento degradato e verifica, dopo ogni aggiornamento Docker/firewall, sia la raggiungibilità inbound sia il blocco delle nuove connessioni outbound.

Non considerare la semplice modifica della rete di esposizione a Compose `internal: true` come sostituto drop-in: sulle versioni recenti di Docker un attachment esclusivamente interno può influire sul port publishing. AEGIS mantiene quindi interne le reti management e applica il controllo egress al confine di forwarding dell'host.

### Isolamento dell'identità sensore

Il deployment Compose standard assegna segreti di ingestione distinti ai decoy SSH, web e legacy. Il collector li riceve tramite `AEGIS_SENSOR_KEYS`, che funziona come allowlist: quando la mappa è configurata, `AEGIS_INGEST_API_KEY` condivisa non viene accettata come fallback e gli ID sensore sconosciuti vengono rifiutati. Le richieste firmate autenticano quindi sia l'integrità del payload sia l'identità attesa del sensore.

I sensori built-in del Compose sono inoltre vincolati alla sorgente tramite `AEGIS_SENSOR_SOURCE_CIDRS`, associata alle CIDR esplicite di `ssh_mgmt`, `web_mgmt` e `legacy_mgmt`. Una chiave sensore valida presentata dalla subnet management sbagliata viene rifiutata. Le richieste provenienti da una CIDR management sensore configurata non possono inoltre accedere a dashboard, UI statica, stato operatore o altre API operatore: da quelle trust zone restano raggiungibili soltanto i due endpoint di ingestione. È un controllo defense-in-depth per un decoy compromesso e non sostituisce rotazione delle chiavi o isolamento di rete.

Suricata utilizza la chiave opzionale `AEGIS_SURICATA_SENSOR_API_KEY` e non viene vincolato a una sorgente dalla mappatura Compose predefinita perché il forwarder incluso viene eseguito sull'host. I sensori personalizzati devono essere aggiunti esplicitamente all'allowlist del collector e, quando opportuno, a `AEGIS_SENSOR_SOURCE_CIDRS`. Dopo una compromissione sospetta è possibile ruotare la singola chiave senza dover cambiare quelle di tutti i decoy.

### Contenimento runtime

I sensori vengono eseguiti con utente non-root e con:

- root filesystem in sola lettura;
- tutte le capability Linux rimosse;
- `no-new-privileges`;
- limiti su PID, CPU, memoria e file descriptor;
- numero massimo di connessioni TCP concorrenti tramite `AEGIS_SENSOR_MAX_CONNECTIONS`;
- timeout applicativi e letture dell'input con dimensioni limitate.

I processi Gunicorn del sensore web e del collector limitano inoltre dimensione della request line/header, keep-alive e numero di richieste per worker.

Per esposizioni Internet utilizza una VLAN/VM dedicata, nega le rotte verso le subnet di produzione, limita l'egress tramite firewall host/rete, monitora anche l'host e ruota periodicamente le credenziali di ingestione. Non montare Docker socket, directory dell'host o credenziali sensibili nei container dei sensori.

Le porte pubbliche predefinite sono volutamente alte (2222, 8080, 2121, 2323). Se le rimappi a 22/80/21/23 tramite firewall/NAT dell'host, documenta la modifica e non aggiungere capability ai container solo per usare porte privilegiate.
