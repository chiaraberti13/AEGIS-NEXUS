# Dedicated PCAP capture sidecars / Sidecar PCAP dedicati

Opt-in full-packet capture for the built-in decoys, as a documented deployment
pattern (ADR 0005). It is **off by default** and ships as a separate Compose
overlay you include explicitly; nothing here runs, or gains raw-socket
privileges, unless you opt in.

## English

### What it is

For each decoy, a **separate single-purpose container** (`docker/pcap/Dockerfile`
— tcpdump only) runs `tcpdump` in a bounded ring buffer against that decoy's own
traffic and writes rotating `.pcap` files to a dedicated `aegis-pcap` volume.

The capture container **shares the decoy's network namespace**
(`network_mode: "service:<decoy>"`). That is the whole trick behind the
capability boundary:

- the **sidecar** holds `CAP_NET_RAW`; the **decoy keeps `cap_drop: ALL`** and
  never gains a capture capability — the rule "never grant a decoy
  `CAP_NET_RAW`" (ADR 0005) is preserved;
- sharing the netns means the sidecar sees **only that decoy's own traffic**,
  nothing lateral; capture is **non-promiscuous** (`tcpdump -p`);
- a **BPF filter** further restricts capture to the decoy's listening port(s);
- tcpdump opens its socket as a capability-stripped root (all caps dropped but
  `NET_RAW`, `no-new-privileges`) and then **drops to `nobody`** (`-Z`);
- the container is **read-only** with a small tmpfs; output goes only to the
  capture volume.

### Bounded disk (ring buffer)

Disk use has a hard upper bound per decoy: a ring of `AEGIS_PCAP_RING_FILES`
files of `AEGIS_PCAP_RING_MB` MB each (tcpdump `-W`/`-C`). When the ring is full
the oldest file is overwritten, so capture never grows without limit. Defaults:
10 × 50 MB = 500 MB per decoy. `AEGIS_PCAP_SNAPLEN` bounds per-packet bytes
(default 262144). All three are validated and clamped by the capture script.

### Enabling it

```
# All always-on decoys:
docker compose -f docker-compose.yml -f docker-compose.pcap.yml --profile pcap up -d

# Also capture the opt-in generic-tcp decoy:
docker compose -f docker-compose.yml -f docker-compose.pcap.yml --profile pcap --profile generic up -d
```

Captures land under the `aegis-pcap` volume, one subdirectory per decoy. Retrieve
them with your normal volume tooling; they are evidence files, so handle them
under the same retention/privacy policy as other exports (`docs/PRIVACY.md`).

To confirm live capture works on your own host (e.g. an Ubuntu machine with
Docker), run the host-only smoke test — it brings up a decoy + its sidecar, sends
a little traffic, and checks a non-empty `.pcap` was written:

```
make pcap-smoke                      # SSH decoy (default)
AEGIS_PCAP_SMOKE_DECOY=web make pcap-smoke
```

It leaves the stack running for inspection (`make down` to stop). This is not a
CI gate — it needs a real Docker daemon and raw-socket privileges.

### Limits and honest caveats

- **Not exercised in CI/unit tests.** Live packet capture needs a privileged
  capture container and real traffic, which the project's unit-test environment
  cannot provide. CI validates the Compose config and the isolation invariants
  (`scripts/verify_compose_isolation.py`: each `*-pcap` sidecar adds exactly
  `CAP_NET_RAW`, drops all else, is read-only + `no-new-privileges`, and shares a
  decoy netns with no network/ports of its own) and builds the image — it does
  **not** prove packets are captured. Validate capture in your own staging.
- **Egress.** Sharing the decoy netns means the sidecar's only network path is
  the decoy's (an exposure + an `internal` management network). The capture
  process makes no outbound connections (tcpdump with `-n`, writing to a local
  volume), but if you need a hard guarantee, apply host/VLAN egress filtering —
  the same perimeter control production decoys already require.
- **Sensitive payloads.** Full-packet capture may record attacker payloads and
  anything a decoy echoes. Treat the volume as sensitive evidence; prefer a
  reduced `AEGIS_PCAP_SNAPLEN` if you only need headers/flows.
- **Scope.** This captures the decoys' own traffic, not arbitrary network spans.
  TLS/JA4-family fingerprints are handled separately (ADR 0005): JA4 via Suricata
  passthrough, not here.

## Italiano

### Cos'è

Per ogni decoy, un **container dedicato a scopo singolo** (`docker/pcap/Dockerfile`
— solo tcpdump) esegue `tcpdump` in un ring buffer limitato sul traffico di quel
decoy e scrive file `.pcap` a rotazione su un volume dedicato `aegis-pcap`.

Il container di cattura **condivide il network namespace del decoy**
(`network_mode: "service:<decoy>"`). È qui che si regge il confine di capability:

- il **sidecar** detiene `CAP_NET_RAW`; il **decoy resta `cap_drop: ALL`** e non
  acquisisce mai una capacità di cattura — la regola "mai concedere `CAP_NET_RAW`
  a un decoy" (ADR 0005) è preservata;
- condividere il netns fa vedere al sidecar **solo il traffico di quel decoy**,
  niente di laterale; la cattura è **non promiscua** (`tcpdump -p`);
- un **filtro BPF** restringe ulteriormente la cattura alle porte in ascolto del
  decoy;
- tcpdump apre il socket come root privo di capability (tutte droppate tranne
  `NET_RAW`, `no-new-privileges`) e poi **scende a `nobody`** (`-Z`);
- il container è **read-only** con una piccola tmpfs; l'output va solo sul volume
  di cattura.

### Disco limitato (ring buffer)

L'uso del disco ha un tetto rigido per decoy: un anello di `AEGIS_PCAP_RING_FILES`
file da `AEGIS_PCAP_RING_MB` MB ciascuno (tcpdump `-W`/`-C`). Quando l'anello è
pieno il file più vecchio viene sovrascritto, quindi la cattura non cresce mai
senza limite. Default: 10 × 50 MB = 500 MB per decoy. `AEGIS_PCAP_SNAPLEN` limita
i byte per pacchetto (default 262144). Tutti e tre sono validati e clampati dallo
script di cattura.

### Come abilitarlo

```
# Tutti i decoy sempre attivi:
docker compose -f docker-compose.yml -f docker-compose.pcap.yml --profile pcap up -d

# Cattura anche il decoy generic-tcp opt-in:
docker compose -f docker-compose.yml -f docker-compose.pcap.yml --profile pcap --profile generic up -d
```

Le catture finiscono sotto il volume `aegis-pcap`, una sottodirectory per decoy.
Sono file di evidenza: trattale con la stessa policy di retention/privacy degli
altri export (`docs/PRIVACY.md`).

Per confermare che la cattura live funzioni sul tuo host (es. una macchina Ubuntu
con Docker), esegui lo smoke test host-only — avvia un decoy + il suo sidecar,
invia un po' di traffico e verifica che sia stato scritto un `.pcap` non vuoto:

```
make pcap-smoke                      # decoy SSH (default)
AEGIS_PCAP_SMOKE_DECOY=web make pcap-smoke
```

Lascia lo stack attivo per l'ispezione (`make down` per fermarlo). Non è un gate
di CI — richiede un daemon Docker reale e privilegi raw-socket.

### Limiti e avvertenze oneste

- **Non esercitato in CI/unit test.** La cattura live richiede un container
  privilegiato e traffico reale, impossibili nell'ambiente di unit test. La CI
  valida la config Compose e gli invarianti di isolamento
  (`scripts/verify_compose_isolation.py`) e builda l'immagine — **non** dimostra
  che i pacchetti vengano catturati. Verifica la cattura nel tuo staging.
- **Egress.** Condividere il netns del decoy fa sì che l'unico percorso di rete
  del sidecar sia quello del decoy (una rete di esposizione + una di management
  `internal`). Il processo di cattura non apre connessioni in uscita (tcpdump con
  `-n`, scrive su un volume locale); per una garanzia rigida applica filtraggio
  egress host/VLAN, lo stesso controllo perimetrale già richiesto dai decoy in
  produzione.
- **Payload sensibili.** La cattura full-packet può registrare payload
  dell'attaccante e quanto il decoy restituisce. Tratta il volume come evidenza
  sensibile; preferisci uno `AEGIS_PCAP_SNAPLEN` ridotto se ti bastano
  header/flussi.
- **Scope.** Cattura il traffico dei decoy, non span di rete arbitrari. I
  fingerprint TLS/JA4 sono gestiti a parte (ADR 0005): JA4 via passthrough
  Suricata, non qui.
