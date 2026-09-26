from __future__ import annotations

import hashlib
import os
import socketserver
import time
import uuid

from ..network_evidence import make_network_evidence
from .base import SensorCapabilities, SensorConfig
from .client import SensorClient
from .registry import register_sensor
from .server import BoundedThreadingTCPServer

MAX_BANNER_BYTES = 512
MAX_PROBE_BYTES = 1024
TIMEOUT = 10.0


def bounded_banner(value: str) -> bytes:
    clean = value.replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    if not clean:
        clean = "Service ready"
    encoded = clean.encode("utf-8", "replace")[:MAX_BANNER_BYTES]
    return encoded + b"\r\n"


class GenericTCPHandler(socketserver.StreamRequestHandler):
    sensor = SensorClient("generic-tcp-decoy-01")
    banner = b"Service ready\r\n"

    def setup(self):
        super().setup()
        self.request.settimeout(TIMEOUT)
        self.sensor_session_id = uuid.uuid4().hex
        self.connection_started = time.monotonic()

    @property
    def source_ip(self) -> str:
        return str(self.client_address[0])

    @property
    def source_port(self) -> int:
        return int(self.client_address[1])

    @property
    def destination_port(self) -> int:
        return int(self.server.server_address[1])

    def observed(self, extra: dict | None = None, *, closed: bool = False) -> dict:
        connection = None
        if closed:
            connection = {
                "duration_ms": max(0, int(round((time.monotonic() - self.connection_started) * 1000)))
            }
        base = {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": "generic-tcp",
            "protocol": "tcp",
            "destination_port": self.destination_port,
            "sensor_session_id": self.sensor_session_id,
            "network": make_network_evidence(
                "sensor_socket",
                "application",
                transport={
                    "protocol": "tcp",
                    "source_port": self.source_port,
                    "destination_port": self.destination_port,
                },
                connection=connection,
            ),
        }
        if extra:
            base.update(extra)
        return base

    def handle(self):
        self.sensor.emit("connection", self.observed())
        self.wfile.write(self.banner)
        self.wfile.flush()
        try:
            probe = self.request.recv(MAX_PROBE_BYTES)
        except TimeoutError:
            probe = b""
        if probe:
            self.sensor.emit(
                "tcp.banner_probe",
                self.observed(
                    {
                        "probe": {
                            "captured_length": len(probe),
                            "sha256": hashlib.sha256(probe).hexdigest(),
                            "content_stored": False,
                        }
                    }
                ),
                "low",
            )

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.sensor.emit("connection.closed", self.observed(closed=True))
        finally:
            super().finish()


@register_sensor
class GenericTCPSensorPlugin:
    name = "generic-tcp"
    capabilities = SensorCapabilities(
        protocols=("tcp",),
        event_types=("connection", "connection.closed", "tcp.banner_probe"),
        interaction_mode="banner_only",
        network_evidence=("transport", "connection"),
        captures_credentials=False,
        captures_commands=False,
        captures_payloads=False,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "generic-tcp-decoy-01")[:96],
            enabled=os.getenv("AEGIS_GENERIC_TCP_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_GENERIC_TCP_BIND", "0.0.0.0"),
            ports={"tcp": int(os.getenv("AEGIS_GENERIC_TCP_PORT", "9000"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
                "banner": os.getenv("AEGIS_GENERIC_TCP_BANNER", "Service ready"),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        GenericTCPHandler.sensor = SensorClient(config.sensor_id)
        GenericTCPHandler.banner = bounded_banner(str(config.options.get("banner", "Service ready")))
        heartbeat = GenericTCPHandler.sensor.start_heartbeat()
        try:
            with BoundedThreadingTCPServer(
                (config.bind_host, config.port("tcp")),
                GenericTCPHandler,
                max_connections=int(config.options.get("max_connections", 32)),
            ) as server:
                server.serve_forever()
        finally:
            heartbeat.stop()


def main():
    GenericTCPSensorPlugin.run(GenericTCPSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
