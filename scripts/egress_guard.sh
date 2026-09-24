#!/usr/bin/env bash
set -euo pipefail

CHAIN="AEGIS_NEXUS_EGRESS"
DOTENV="${AEGIS_ENV_FILE:-.env}"

die() {
  printf 'AEGIS egress guard: %s\n' "$*" >&2
  exit 1
}

dotenv_value() {
  local key="$1"
  [[ -f "$DOTENV" ]] || return 0
  awk -v key="$key" '
    index($0, key "=") == 1 {
      value = substr($0, length(key) + 2)
      sub(/\r$/, "", value)
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
        value = substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  ' "$DOTENV"
}

resolve_subnet() {
  local key="$1"
  local fallback="$2"
  local current="${!key:-}"
  if [[ -n "$current" ]]; then
    printf '%s\n' "$current"
    return
  fi
  current="$(dotenv_value "$key")"
  printf '%s\n' "${current:-$fallback}"
}

require_host_firewall() {
  [[ "${EUID}" -eq 0 ]] || die "run as root (for example: sudo make egress-guard)"
  command -v iptables >/dev/null 2>&1 || die "iptables is required on the Docker host"
  iptables -nL DOCKER-USER >/dev/null 2>&1 || die "DOCKER-USER chain not found; start Docker before installing the guard"
}

subnets=(
  "$(resolve_subnet AEGIS_SSH_EXPOSURE_SUBNET 172.30.101.0/24)"
  "$(resolve_subnet AEGIS_WEB_EXPOSURE_SUBNET 172.30.102.0/24)"
  "$(resolve_subnet AEGIS_LEGACY_EXPOSURE_SUBNET 172.30.103.0/24)"
  "$(resolve_subnet AEGIS_SMTP_EXPOSURE_SUBNET 172.30.104.0/24)"
)

validate_subnets() {
  local subnet ip prefix octet
  local -a octets
  for subnet in "${subnets[@]}"; do
    [[ "$subnet" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "invalid IPv4 CIDR: $subnet"
    IFS=/ read -r ip prefix <<< "$subnet"
    IFS=. read -r -a octets <<< "$ip"
    (( ${#octets[@]} == 4 )) || die "invalid IPv4 CIDR: $subnet"
    for octet in "${octets[@]}"; do
      (( 10#$octet <= 255 )) || die "invalid IPv4 CIDR: $subnet"
    done
    (( 10#$prefix <= 32 )) || die "invalid IPv4 CIDR: $subnet"
  done
}

validate_only() {
  validate_subnets
  printf 'Exposure CIDRs are syntactically valid:\n'
  printf '  %s\n' "${subnets[@]}"
}

install_guard() {
  require_host_firewall
  validate_subnets
  iptables -N "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN"
  iptables -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1 || iptables -I DOCKER-USER 1 -j "$CHAIN"

  local subnet
  for subnet in "${subnets[@]}"; do
    # Replies to Internet-originated honeypot connections remain possible.
    iptables -A "$CHAIN" -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    # New traffic initiated from a decoy exposure interface is denied.
    iptables -A "$CHAIN" -s "$subnet" -j DROP
  done
  iptables -A "$CHAIN" -j RETURN

  printf 'Installed %s for:\n' "$CHAIN"
  printf '  %s\n' "${subnets[@]}"
  printf 'Verify from each decoy that inbound published ports still work and new outbound connections fail.\n'
}

remove_guard() {
  require_host_firewall
  while iptables -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
    iptables -D DOCKER-USER -j "$CHAIN"
  done
  iptables -F "$CHAIN" >/dev/null 2>&1 || true
  iptables -X "$CHAIN" >/dev/null 2>&1 || true
  printf 'Removed %s.\n' "$CHAIN"
}

status_guard() {
  require_host_firewall
  if ! iptables -nL "$CHAIN" >/dev/null 2>&1; then
    printf '%s is not installed.\n' "$CHAIN"
    exit 1
  fi
  iptables -S DOCKER-USER | grep -- "-j $CHAIN" || true
  iptables -S "$CHAIN"
}

case "${1:-status}" in
  install) install_guard ;;
  remove) remove_guard ;;
  status) status_guard ;;
  validate) validate_only ;;
  *) die "usage: $0 {install|status|remove|validate}" ;;
esac
