"""Prometheus text-format metrics rendering (collector-side, aggregate only).

Only fixed metric names and a fixed set of state labels are emitted — no
attacker-controlled value (sensor id, IP, …) ever becomes a metric name or
label, so the exposition cannot be used for metrics/log injection.
"""

from __future__ import annotations

from typing import Any

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
_PLATFORM_STATES = ("healthy", "degraded", "critical")


def _gauge(lines: list[str], name: str, value: Any, help_text: str) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        value = 1 if value else 0
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name} {value}")


def render_prometheus(health: dict[str, Any], telemetry: dict[str, Any]) -> str:
    lines: list[str] = []
    storage = health.get("storage") or {}

    # Platform state as an enum-style gauge (exactly one series is 1).
    current = str(health.get("state") or "")
    lines.append("# HELP aegis_platform_state Current platform state (1 for the active state).")
    lines.append("# TYPE aegis_platform_state gauge")
    for state in _PLATFORM_STATES:
        lines.append(f'aegis_platform_state{{state="{state}"}} {1 if state == current else 0}')

    _gauge(lines, "aegis_ready", health.get("ready"), "1 when the collector is fully ready.")
    _gauge(lines, "aegis_database_ready", health.get("database_ready"), "1 when the database is reachable.")
    _gauge(lines, "aegis_schema_current", (health.get("database_schema") or {}).get("current"),
           "1 when the database schema matches the latest supported version.")
    _gauge(lines, "aegis_storage_ready", health.get("storage_ready"), "1 when free disk is above the minimum.")
    _gauge(lines, "aegis_storage_free_bytes", health.get("storage_free_bytes"), "Free bytes on the database volume.")
    _gauge(lines, "aegis_min_free_bytes", health.get("min_free_bytes"), "Configured minimum free bytes.")
    _gauge(lines, "aegis_database_size_bytes", storage.get("database_size_bytes"),
           "On-disk size of the database and its WAL/SHM sidecars.")
    _gauge(lines, "aegis_events_total", storage.get("event_count"), "Stored event count.")
    _gauge(lines, "aegis_events_max", storage.get("max_events"), "Configured maximum stored events.")
    _gauge(lines, "aegis_events_capacity_used_fraction", storage.get("capacity_used_fraction"),
           "Stored events as a fraction of the configured maximum.")
    _gauge(lines, "aegis_retention_days", storage.get("retention_days"), "Configured event retention in days.")

    _gauge(lines, "aegis_sensors_configured", telemetry.get("configured_sensors"), "Configured sensor identities.")
    _gauge(lines, "aegis_sensors_with_recent_telemetry", telemetry.get("configured_with_recent_telemetry"),
           "Configured sensors with recent telemetry in the window.")
    _gauge(lines, "aegis_sensors_healthy_heartbeat", telemetry.get("configured_with_healthy_heartbeat"),
           "Configured sensors with a healthy heartbeat.")
    _gauge(lines, "aegis_sensors_with_sequence_gaps", telemetry.get("sensors_with_sequence_gaps"),
           "Sensors with detected event-sequence gaps (evidence loss).")
    _gauge(lines, "aegis_missing_sequenced_events", telemetry.get("missing_sequenced_events"),
           "Events a sensor numbered but the collector never stored (evidence loss).")

    return "\n".join(lines) + "\n"
