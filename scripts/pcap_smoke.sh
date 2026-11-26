#!/usr/bin/env bash
# Manual smoke test for the opt-in PCAP capture sidecars (ADR 0005).
#
# HOST-ONLY: this needs a running Docker daemon, raw-socket privileges and real
# traffic, so it is NOT part of CI (which only config/isolation-validates). Run
# it on a real host (e.g. your Ubuntu machine) to confirm live capture works:
#
#   make pcap-smoke                 # SSH decoy (default)
#   AEGIS_PCAP_SMOKE_DECOY=web make pcap-smoke
#
# It brings up the pcap profile, sends a little traffic to the chosen decoy's
# published port, then checks that the sidecar wrote a non-empty .pcap. It leaves
# the stack running so you can inspect; tear down with `make down`.
set -euo pipefail

decoy="${AEGIS_PCAP_SMOKE_DECOY:-ssh}"
case "$decoy" in
    ssh)     sidecar="ssh-pcap";     capdir="ssh-decoy-01";     port="${AEGIS_PUBLIC_SSH_PORT:-2222}" ;;
    web)     sidecar="web-pcap";     capdir="web-decoy-01";     port="${AEGIS_PUBLIC_WEB_PORT:-8080}" ;;
    smtp)    sidecar="smtp-pcap";    capdir="smtp-decoy-01";    port="${AEGIS_PUBLIC_SMTP_PORT:-2525}" ;;
    redis)   sidecar="redis-pcap";   capdir="redis-decoy-01";   port="${AEGIS_PUBLIC_REDIS_PORT:-6379}" ;;
    mysql)   sidecar="mysql-pcap";   capdir="mysql-decoy-01";   port="${AEGIS_PUBLIC_MYSQL_PORT:-3306}" ;;
    smb)     sidecar="smb-pcap";     capdir="smb-decoy-01";     port="${AEGIS_PUBLIC_SMB_PORT:-445}" ;;
    *) echo "pcap-smoke: unknown decoy '$decoy' (try: ssh web smtp redis mysql smb)" >&2; exit 2 ;;
esac

compose() { docker compose -f docker-compose.yml -f docker-compose.pcap.yml "$@"; }

echo "pcap-smoke: checking prerequisites..."
command -v docker >/dev/null || { echo "docker not found — run this on a host with Docker" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "Docker daemon not reachable — start Docker and retry" >&2; exit 2; }
[ -f .env ] || { echo "No .env — copy .env.example to .env and set the sensor API keys first" >&2; exit 2; }

echo "pcap-smoke: starting the '${decoy}' decoy + its capture sidecar..."
compose --profile pcap up -d "${decoy}-decoy" "${sidecar}"

echo "pcap-smoke: waiting for the sidecar to start capturing..."
sleep 5

echo "pcap-smoke: generating a little traffic to 127.0.0.1:${port}..."
for _ in 1 2 3; do
    # A bare TCP connect (+ a short line) is enough to produce packets the
    # BPF-filtered sidecar will record; no real protocol exchange is needed.
    (exec 3<>"/dev/tcp/127.0.0.1/${port}" && printf 'SSH-2.0-aegis-pcap-smoke\r\n' >&3 && sleep 1 && exec 3<&- ) 2>/dev/null || true
done

echo "pcap-smoke: letting tcpdump flush..."
sleep 3

echo "pcap-smoke: inspecting the capture volume (${sidecar}:/capture/${capdir})..."
listing="$(compose exec -T "${sidecar}" sh -c "ls -l /capture/${capdir} 2>/dev/null" || true)"
echo "${listing}"

if echo "${listing}" | grep -qE '[1-9][0-9]*[[:space:]].*\.pcap'; then
    echo "pcap-smoke: PASS — a non-empty .pcap was written. Live capture works."
    echo "pcap-smoke: stack left running; tear down with 'make down'."
    exit 0
fi

echo "pcap-smoke: FAIL — no non-empty .pcap found." >&2
echo "pcap-smoke: check 'docker compose -f docker-compose.yml -f docker-compose.pcap.yml logs ${sidecar}'." >&2
exit 1
