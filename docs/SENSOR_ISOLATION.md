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

The telemetry path is narrow but it is not a hardware data diode. If an Internet-facing sensor were compromised through a software defect, the Docker host firewall remains responsible for preventing access to production networks and for restricting outbound Internet access.

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

Il percorso di telemetria è ristretto ma non equivale a un data diode hardware. Se un sensore esposto a Internet venisse compromesso tramite un difetto software, il firewall dell'host deve comunque impedire l'accesso alle reti di produzione e limitare l'uscita verso Internet.

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
