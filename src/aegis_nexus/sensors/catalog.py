from __future__ import annotations

from .registry import SensorRegistry, registry


def load_builtin_sensors(target: SensorRegistry | None = None) -> SensorRegistry:
    # Imports register the built-in plugins. Keep this explicit so the collector
    # does not import protocol runtimes or generate sensor resources at startup.
    from .legacy import LegacySensorPlugin
    from .ssh_decoy import SSHSensorPlugin
    from .web_decoy import WebSensorPlugin

    selected = target or registry
    for plugin in (SSHSensorPlugin, WebSensorPlugin, LegacySensorPlugin):
        selected.register(plugin)
    return selected
