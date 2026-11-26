#!/bin/sh
# AEGIS-NEXUS dedicated PCAP capture (opt-in, ADR 0005).
#
# Runs tcpdump in a bounded ring buffer against a single decoy's own traffic
# (this container shares that decoy's network namespace via
# `network_mode: service:<decoy>`), filtered by BPF to the decoy's port(s).
# Design invariants, enforced here and in docker-compose.pcap.yml:
#   * capture capability (CAP_NET_RAW) lives in THIS sidecar, never in a decoy;
#   * non-promiscuous (-p): only the decoy's own packets, nothing lateral;
#   * bounded disk: a ring buffer of AEGIS_PCAP_RING_FILES files of
#     AEGIS_PCAP_RING_MB MB each is the hard upper bound — old files are
#     overwritten, never grown without limit;
#   * least privilege: tcpdump opens the socket, then drops to `nobody` (-Z).
set -eu

sensor="${AEGIS_PCAP_SENSOR:?set AEGIS_PCAP_SENSOR (owning decoy name)}"
bpf="${AEGIS_PCAP_BPF:?set AEGIS_PCAP_BPF (e.g. \"tcp port 2222\")}"
snaplen="${AEGIS_PCAP_SNAPLEN:-262144}"
ring_mb="${AEGIS_PCAP_RING_MB:-50}"
ring_files="${AEGIS_PCAP_RING_FILES:-10}"
out_dir="${AEGIS_PCAP_OUT_DIR:-/capture}"

# Bound and validate every numeric knob (defence in depth: these come from the
# deployment env, not an attacker, but we still refuse nonsense rather than hand
# tcpdump an unbounded value).
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
for pair in "snaplen=$snaplen" "ring_mb=$ring_mb" "ring_files=$ring_files"; do
    name=${pair%%=*}; value=${pair#*=}
    if ! is_uint "$value" || [ "$value" -lt 1 ]; then
        echo "aegis-pcap: $name must be a positive integer, got '$value'" >&2
        exit 2
    fi
done
# Clamp to sane maxima so a typo cannot fill the disk or overflow tcpdump.
[ "$snaplen" -gt 262144 ] && snaplen=262144
[ "$ring_mb" -gt 1024 ] && ring_mb=1024
[ "$ring_files" -gt 1000 ] && ring_files=1000

dest="${out_dir}/${sensor}"
mkdir -p "$dest"
# Let the post-drop `nobody` user write the rotating files.
chown -R nobody:nogroup "$dest" 2>/dev/null || true

echo "aegis-pcap: capturing ${sensor} (${bpf}); ring=${ring_files}x${ring_mb}MB snaplen=${snaplen}" >&2

# -p  no promiscuous mode (only this netns's own traffic)
# -n  no name resolution (no outbound DNS from the capture box)
# -s  bounded snaplen
# -C  rotate at ring_mb million bytes;  -W  keep ring_files files (ring buffer)
# -Z  drop to nobody after the capture socket is open
# -w  rotating output under the dedicated capture volume
exec tcpdump -p -n -i any \
    -s "$snaplen" \
    -C "$ring_mb" -W "$ring_files" \
    -Z nobody \
    -w "${dest}/${sensor}.pcap" \
    ${AEGIS_PCAP_TCPDUMP_EXTRA:-} \
    "$bpf"
