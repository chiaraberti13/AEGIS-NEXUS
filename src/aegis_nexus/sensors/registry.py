from __future__ import annotations

from typing import Any

from .base import SensorPlugin


class SensorRegistry:
    def __init__(self):
        self._plugins: dict[str, type[SensorPlugin]] = {}

    def register(self, plugin: type[SensorPlugin]) -> type[SensorPlugin]:
        name = str(getattr(plugin, "name", "")).strip().lower()
        if not name:
            raise ValueError("sensor plugin requires a name")
        if name in self._plugins and self._plugins[name] is not plugin:
            raise ValueError(f"sensor plugin already registered: {name}")
        capabilities = getattr(plugin, "capabilities", None)
        if capabilities is None:
            raise ValueError("sensor plugin requires capabilities")
        capabilities.as_dict()
        self._plugins[name] = plugin
        return plugin

    def get(self, name: str) -> type[SensorPlugin]:
        key = str(name).strip().lower()
        try:
            return self._plugins[key]
        except KeyError as exc:
            raise KeyError(f"unknown sensor plugin: {key}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._plugins))

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "capabilities": self._plugins[name].capabilities.as_dict(),
            }
            for name in self.names()
        ]


registry = SensorRegistry()


def register_sensor(plugin: type[SensorPlugin]) -> type[SensorPlugin]:
    return registry.register(plugin)
