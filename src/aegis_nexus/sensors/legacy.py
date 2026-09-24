from __future__ import annotations

import os
import socketserver
import threading
import time
import uuid
from typing import BinaryIO

from .base import SensorCapabilities, SensorConfig
from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient
from ..network_evidence import make_network_evidence
from .server import BoundedThreadingTCPServer
from .registry import register_sensor

MAX_LINE = 512
TIMEOUT = 15.0


def _readline_with_status(stream: BinaryIO) -> tuple[str, dict | None]:
    data = stream.readline(MAX_LINE + 1)
    if len(data) > MAX_LINE:
        return "", {
            "reason": "line_too_long",
            "limit": MAX_LINE,
            "bytes_observed_at_least": len(data),
        }
    return data.decode("utf-8", "replace").strip(), None


def _readline(stream: BinaryIO) -> str:
    line, _status = _readline_with_status(stream)
    return line


class BaseHandler(socketserver.StreamRequestHandler):
    service = "legacy"
    sensor = SensorClient("legacy-01")

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

    def emit(self, event_type: str, observed: dict, severity: str = "info"):
        destination_port = int(observed.get("destination_port") or self.destination_port)
        connection = None
        if event_type == "connection.closed":
            connection = {
                "duration_ms": max(
                    0,
                    int(round((time.monotonic() - self.connection_started) * 1000)),
                )
            }
        base = {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": self.service,
            "protocol": "tcp",
            "destination_port": destination_port,
            "sensor_session_id": self.sensor_session_id,
            "network": make_network_evidence(
                "sensor_socket",
                "application",
                transport={
                    "protocol": "tcp",
                    "source_port": self.source_port,
                    "destination_port": destination_port,
                },
                connection=connection,
            ),
            **observed,
        }
        self.sensor.emit(event_type, base, severity)

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.emit("connection.closed", {"destination_port": self.destination_port})
        finally:
            super().finish()

    def read_line(self, path: str) -> str | None:
        line, rejected = _readline_with_status(self.rfile)
        if rejected is None:
            return line
        self.emit(
            "sensor.input_rejected",
            {
                "destination_port": self.destination_port,
                "sensor_capture": {
                    "rejected": True,
                    "path": path,
                    **rejected,
                },
            },
            "low",
        )
        return None


class FTPHandler(BaseHandler):
    service = "ftp"

    def handle(self):
        self.emit("connection", {"destination_port": self.destination_port})
        self.wfile.write(b"220 Meridian FTP Service\r\n")
        username = ""
        username_audit: dict = {}
        for _ in range(6):
            line = self.read_line("observed.legacy_line")
            if line is None or not line:
                break
            command, _, argument = line.partition(" ")
            command = command.upper()
            if command == "USER":
                username_audit = {}
                username = bounded_text(
                    argument,
                    128,
                    "observed.credential.username",
                    username_audit,
                )
                self.wfile.write(b"331 Password required\r\n")
            elif command == "PASS":
                audit = {
                    "truncated_fields": list(username_audit.get("truncated_fields", []))
                } if username_audit.get("truncated_fields") else {}
                password = bounded_text(
                    argument,
                    4096,
                    "observed.credential.password",
                    audit,
                    fingerprint_original=True,
                )
                observed = {
                    "destination_port": self.destination_port,
                    "credential": {"username": username, "password": password},
                }
                attach_capture_metadata(observed, audit)
                self.emit("credential", observed, "medium")
                self.wfile.write(b"530 Login incorrect\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 Goodbye\r\n")
                break
            else:
                audit: dict = {}
                captured_line = bounded_text(line, 256, "observed.command", audit)
                observed = {"destination_port": self.destination_port, "command": captured_line}
                attach_capture_metadata(observed, audit)
                self.emit("legacy.command", observed, "low")
                self.wfile.write(b"500 Command not understood\r\n")


class TelnetHandler(BaseHandler):
    service = "telnet"

    def handle(self):
        self.emit("connection", {"destination_port": self.destination_port})
        self.wfile.write(b"Meridian Gateway\r\nlogin: ")
        username_line = self.read_line("observed.credential.username")
        if username_line is None:
            return
        audit: dict = {}
        username = bounded_text(
            username_line,
            128,
            "observed.credential.username",
            audit,
        )
        self.wfile.write(b"Password: ")
        password_line = self.read_line("observed.credential.password")
        if password_line is None:
            return
        password = bounded_text(
            password_line,
            4096,
            "observed.credential.password",
            audit,
            fingerprint_original=True,
        )
        observed = {
            "destination_port": self.destination_port,
            "credential": {"username": username, "password": password},
        }
        attach_capture_metadata(observed, audit)
        self.emit("credential", observed, "medium")
        self.wfile.write(b"Login incorrect\r\n")


@register_sensor
class LegacySensorPlugin:
    name = "legacy"
    capabilities = SensorCapabilities(
        protocols=("ftp", "telnet", "tcp"),
        event_types=("connection", "connection.closed", "credential", "legacy.command", "sensor.input_rejected"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
        captures_credentials=True,
        captures_commands=True,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "legacy-decoy-01")[:96],
            enabled=os.getenv("AEGIS_LEGACY_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_LEGACY_BIND", "0.0.0.0"),
            ports={
                "ftp": int(os.getenv("AEGIS_FTP_PORT", "2121")),
                "telnet": int(os.getenv("AEGIS_TELNET_PORT", "2323")),
            },
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        max_connections = int(config.options.get("max_connections", 32))
        FTPHandler.sensor = SensorClient(config.sensor_id)
        TelnetHandler.sensor = FTPHandler.sensor
        ftp = BoundedThreadingTCPServer(
            (config.bind_host, config.port("ftp")),
            FTPHandler,
            max_connections=max_connections,
        )
        telnet = BoundedThreadingTCPServer(
            (config.bind_host, config.port("telnet")),
            TelnetHandler,
            max_connections=max_connections,
        )
        threads = [
            threading.Thread(target=ftp.serve_forever, daemon=True),
            threading.Thread(target=telnet.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


def main():
    LegacySensorPlugin.run(LegacySensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
