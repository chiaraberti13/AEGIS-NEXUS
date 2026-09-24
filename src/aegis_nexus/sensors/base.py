from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

SENSOR_PLUGIN_SCHEMA_VERSION = "1.0"
INTERACTION_MODES = {"emulated", "banner_only", "telemetry_only"}


@dataclass(frozen=True)
class SensorCapabilities:
    protocols: tuple[str, ...]
    event_types: tuple[str, ...]
    interaction_mode: str = "emulated"
    network_evidence: tuple[str, ...] = ()
    captures_credentials: bool = False
    captures_commands: bool = False
    captures_payloads: bool = False
    executes_attacker_input: bool = False

    def as_dict(self) -> dict[str, Any]:
        if self.interaction_mode not in INTERACTION_MODES:
            raise ValueError("invalid sensor interaction mode")
        if self.executes_attacker_input:
            raise ValueError("AEGIS sensor plugins must not execute attacker input")
        return {
            "schema_version": SENSOR_PLUGIN_SCHEMA_VERSION,
            "protocols": list(self.protocols),
            "event_types": list(self.event_types),
            "interaction_mode": self.interaction_mode,
            "network_evidence": list(self.network_evidence),
            "captures_credentials": self.captures_credentials,
            "captures_commands": self.captures_commands,
            "captures_payloads": self.captures_payloads,
            "executes_attacker_input": False,
        }


@dataclass(frozen=True)
class SensorConfig:
    sensor_id: str
    enabled: bool = True
    bind_host: str = "0.0.0.0"
    ports: dict[str, int] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    def port(self, name: str) -> int:
        value = int(self.ports[name])
        if not 1 <= value <= 65535:
            raise ValueError(f"invalid sensor port: {name}")
        return value


class SensorPlugin(Protocol):
    name: str
    capabilities: SensorCapabilities

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        """Build a bounded declarative config from the process environment."""

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        """Run the sensor until shutdown."""
