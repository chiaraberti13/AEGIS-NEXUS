from __future__ import annotations

from .registry import SensorRegistry, registry


def load_builtin_sensors(target: SensorRegistry | None = None) -> SensorRegistry:
    # Imports register the built-in plugins. Keep this explicit so the collector
    # does not import protocol runtimes or generate sensor resources at startup.
    from .legacy import LegacySensorPlugin
    from .mysql_decoy import MySQLSensorPlugin
    from .redis_decoy import RedisSensorPlugin
    from .smb_decoy import SMBSensorPlugin
    from .ssh_decoy import SSHSensorPlugin
    from .smtp_decoy import SMTPSensorPlugin
    from .web_decoy import WebSensorPlugin

    selected = target or registry
    for plugin in (SSHSensorPlugin, WebSensorPlugin, LegacySensorPlugin, SMTPSensorPlugin, RedisSensorPlugin, MySQLSensorPlugin, SMBSensorPlugin):
        selected.register(plugin)
    return selected
