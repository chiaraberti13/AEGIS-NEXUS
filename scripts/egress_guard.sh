#!/usr/bin/env bash
set -euo pipefail

CHAIN="AEGIS_NEXUS_EGRESS"
CHAIN6="AEGIS_NEXUS_EGRESS6"
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
  command -v ip6tables >/dev/null 2>&1 || die "ip6tables is required on the Docker host for dual-stack decoys"
  iptables -nL DOCKER-USER >/dev/null 2>&1 || die "DOCKER-USER chain not found; start Docker before installing the guard"
  ip6tables -nL DOCKER-USER >/dev/null 2>&1 || die "IPv6 DOCKER-USER chain not found; start Docker with IPv6 networking before installing the guard"
}

subnets=(
  "$(resolve_subnet AEGIS_SSH_EXPOSURE_SUBNET 172.30.101.0/24)"
  "$(resolve_subnet AEGIS_WEB_EXPOSURE_SUBNET 172.30.102.0/24)"
  "$(resolve_subnet AEGIS_LEGACY_EXPOSURE_SUBNET 172.30.103.0/24)"
  "$(resolve_subnet AEGIS_SMTP_EXPOSURE_SUBNET 172.30.104.0/24)"
  "$(resolve_subnet AEGIS_REDIS_EXPOSURE_SUBNET 172.30.105.0/24)"
  "$(resolve_subnet AEGIS_MYSQL_EXPOSURE_SUBNET 172.30.106.0/24)"
  "$(resolve_subnet AEGIS_SMB_EXPOSURE_SUBNET 172.30.107.0/24)"
  "$(resolve_subnet AEGIS_GENERIC_EXPOSURE_SUBNET 172.30.108.0/24)"
)

subnets6=(
  "$(resolve_subnet AEGIS_SSH_EXPOSURE_SUBNET_V6 fd30:101::/64)"
  "$(resolve_subnet AEGIS_WEB_EXPOSURE_SUBNET_V6 fd30:102::/64)"
  "$(resolve_subnet AEGIS_LEGACY_EXPOSURE_SUBNET_V6 fd30:103::/64)"
  "$(resolve_subnet AEGIS_SMTP_EXPOSURE_SUBNET_V6 fd30:104::/64)"
  "$(resolve_subnet AEGIS_REDIS_EXPOSURE_SUBNET_V6 fd30:105::/64)"
  "$(resolve_subnet AEGIS_MYSQL_EXPOSURE_SUBNET_V6 fd30:106::/64)"
  "$(resolve_subnet AEGIS_SMB_EXPOSURE_SUBNET_V6 fd30:107::/64)"
  "$(resolve_subnet AEGIS_GENERIC_EXPOSURE_SUBNET_V6 fd30:108::/64)"
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
  command -v python3 >/dev/null 2>&1 || die "python3 is required to validate IPv6 CIDRs"
  local subnet6
  for subnet6 in "${subnets6[@]}"; do
    python3 - "$subnet6" <<'PY' || die "invalid IPv6 CIDR: $subnet6"
import ipaddress
import sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
if network.version != 6:
    raise SystemExit(1)
PY
  done
}

validate_only() {
  validate_subnets
  printf 'Exposure IPv4 CIDRs are syntactically valid:\n'
  printf '  %s\n' "${subnets[@]}"
  printf 'Exposure IPv6 CIDRs are syntactically valid:\n'
  printf '  %s\n' "${subnets6[@]}"
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

  ip6tables -N "$CHAIN6" 2>/dev/null || true
  ip6tables -F "$CHAIN6"
  ip6tables -C DOCKER-USER -j "$CHAIN6" >/dev/null 2>&1 || ip6tables -I DOCKER-USER 1 -j "$CHAIN6"
  local subnet6
  for subnet6 in "${subnets6[@]}"; do
    ip6tables -A "$CHAIN6" -s "$subnet6" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    ip6tables -A "$CHAIN6" -s "$subnet6" -j DROP
  done
  ip6tables -A "$CHAIN6" -j RETURN

  printf 'Installed %s for IPv4:\n' "$CHAIN"
  printf '  %s\n' "${subnets[@]}"
  printf 'Installed %s for IPv6:\n' "$CHAIN6"
  printf '  %s\n' "${subnets6[@]}"
  printf 'Verify from each decoy that inbound published ports still work and new outbound IPv4/IPv6 connections fail.\n'
}

remove_guard() {
  require_host_firewall
  while iptables -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
    iptables -D DOCKER-USER -j "$CHAIN"
  done
  iptables -F "$CHAIN" >/dev/null 2>&1 || true
  iptables -X "$CHAIN" >/dev/null 2>&1 || true
  while ip6tables -C DOCKER-USER -j "$CHAIN6" >/dev/null 2>&1; do
    ip6tables -D DOCKER-USER -j "$CHAIN6"
  done
  ip6tables -F "$CHAIN6" >/dev/null 2>&1 || true
  ip6tables -X "$CHAIN6" >/dev/null 2>&1 || true
  printf 'Removed %s and %s.\n' "$CHAIN" "$CHAIN6"
}

status_guard() {
  require_host_firewall
  if ! iptables -nL "$CHAIN" >/dev/null 2>&1; then
    printf '%s is not installed.\n' "$CHAIN"
    exit 1
  fi
  iptables -S DOCKER-USER | grep -- "-j $CHAIN" || true
  iptables -S "$CHAIN"
  ip6tables -S DOCKER-USER | grep -- "-j $CHAIN6" || true
  ip6tables -S "$CHAIN6"
}

case "${1:-status}" in
  install) install_guard ;;
  remove) remove_guard ;;
  status) status_guard ;;
  validate) validate_only ;;
  *) die "usage: $0 {install|status|remove|validate}" ;;
esac
