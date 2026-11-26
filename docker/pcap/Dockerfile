# Dedicated PCAP capture sidecar (opt-in, ADR 0005).
#
# A minimal, single-purpose image: tcpdump and nothing else. It is NEVER part of
# a decoy — it runs as its own container that shares a decoy's network namespace
# (docker-compose.pcap.yml), holding CAP_NET_RAW while the decoy keeps
# cap_drop: ALL. The container is run read-only, with no-new-privileges and all
# capabilities dropped except NET_RAW; tcpdump opens its capture socket and then
# drops to the unprivileged `nobody` user (-Z) for the rest of its life.
FROM debian:bookworm-slim

# tcpdump only; no shell tooling, no package manager left usable at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY docker/pcap/capture.sh /usr/local/bin/aegis-pcap-capture
RUN chmod 0555 /usr/local/bin/aegis-pcap-capture

# The capture process starts as root solely so tcpdump can open the AF_PACKET
# socket with CAP_NET_RAW; it immediately drops to `nobody` via tcpdump -Z.
ENTRYPOINT ["/usr/local/bin/aegis-pcap-capture"]
