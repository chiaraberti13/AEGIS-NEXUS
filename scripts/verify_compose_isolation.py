from __future__ import annotations

import ipaddress
import json
import sys

SENSORS = {
    "ssh-decoy": ("ssh_exposure", "ssh_mgmt"),
    "web-decoy": ("web_exposure", "web_mgmt"),
    "legacy-decoy": ("legacy_exposure", "legacy_mgmt"),
    "smtp-decoy": ("smtp_exposure", "smtp_mgmt"),
    "redis-decoy": ("redis_exposure", "redis_mgmt"),
    "mysql-decoy": ("mysql_exposure", "mysql_mgmt"),
    "smb-decoy": ("smb_exposure", "smb_mgmt"),
    "generic-tcp-decoy": ("generic_exposure", "generic_mgmt"),
}


def fail(message: str) -> None:
    raise SystemExit(f"compose isolation check failed: {message}")


def main() -> None:
    payload = json.load(sys.stdin)
    services = payload.get("services") or {}
    networks = payload.get("networks") or {}

    for service_name, expected_networks in SENSORS.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            fail(f"missing sensor service {service_name}")
        if service.get("read_only") is not True:
            fail(f"{service_name} root filesystem is not read-only")
        if "ALL" not in (service.get("cap_drop") or []):
            fail(f"{service_name} does not drop all capabilities")
        security_opt = service.get("security_opt") or []
        if not any(str(value).replace("=", ":") == "no-new-privileges:true" for value in security_opt):
            fail(f"{service_name} lacks no-new-privileges")
        attached = set((service.get("networks") or {}).keys())
        if attached != set(expected_networks):
            fail(f"{service_name} networks {sorted(attached)} != {sorted(expected_networks)}")
        environment = service.get("environment") or {}
        bind_keys = [key for key in environment if str(key).endswith("_BIND")]
        if not bind_keys or any(str(environment.get(key)) != "::" for key in bind_keys):
            fail(f"{service_name} is not configured for dual-stack listening")
        if service_name == "web-decoy":
            command = [str(value) for value in (service.get("command") or [])]
            if "[::]:8080" not in command:
                fail("web-decoy gunicorn is not bound to IPv6 any-address")
        exposure = networks.get(expected_networks[0]) or {}
        if exposure.get("enable_ipv6") is not True:
            fail(f"{expected_networks[0]} is not IPv6-enabled")
        configs = ((exposure.get("ipam") or {}).get("config") or [])
        subnets = [str(item.get("subnet") or "") for item in configs if isinstance(item, dict)]
        try:
            versions = {ipaddress.ip_network(subnet, strict=False).version for subnet in subnets if subnet}
        except ValueError as exc:
            fail(f"{expected_networks[0]} has invalid IPAM subnet: {exc}")
        if versions != {4, 6}:
            fail(f"{expected_networks[0]} must have both IPv4 and IPv6 subnets")

    collector_networks = set(((services.get("collector") or {}).get("networks") or {}).keys())
    forbidden = {exposure for exposure, _management in SENSORS.values()}
    leaked = sorted(collector_networks & forbidden)
    if leaked:
        fail(f"collector attached to exposure networks: {leaked}")

    print("Compose sensor isolation invariants verified for all built-in decoys.")


if __name__ == "__main__":
    main()
