from __future__ import annotations

import hashlib
import os
import socketserver
import time
import uuid

from ..network_evidence import make_network_evidence
from .base import SensorCapabilities, SensorConfig
from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient
from .registry import register_sensor
from .persona import load_persona
from .server import BoundedThreadingTCPServer

MAX_LINE = 1024
PERSONA = load_persona()

TIMEOUT = 20.0


class SMTPHandler(socketserver.StreamRequestHandler):
    sensor = SensorClient("smtp-decoy-01")

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
            "service": "smtp",
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

    def emit(self, event_type: str, extra: dict | None = None, severity: str = "info"):
        self.sensor.emit(event_type, self.observed(extra), severity)

    def read_line(self) -> str | None:
        raw = self.rfile.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            self.emit(
                "sensor.input_rejected",
                {
                    "sensor_capture": {
                        "rejected": True,
                        "path": "observed.smtp_line",
                        "reason": "line_too_long",
                        "limit": MAX_LINE,
                        "bytes_observed_at_least": len(raw),
                    }
                },
                "low",
            )
            return None
        return raw.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        self.emit("connection")
        self.wfile.write(f"220 {PERSONA.smtp_hostname} ESMTP ready\r\n".encode("ascii", "replace"))
        for _ in range(20):
            line = self.read_line()
            if line is None or not line:
                break
            command, _, argument = line.partition(" ")
            verb = command.upper()[:16]
            audit: dict = {}

            if verb in {"EHLO", "HELO"}:
                value = bounded_text(argument, 255, "observed.smtp.helo", audit)
                observed = {"smtp": {"command": verb, "helo": value}}
                attach_capture_metadata(observed, audit)
                self.emit("smtp.command", observed)
                self.wfile.write(f"250-{PERSONA.smtp_hostname}\r\n250 AUTH PLAIN LOGIN\r\n".encode("ascii", "replace"))
            elif verb == "AUTH":
                mechanism, _, blob = argument.partition(" ")
                auth = {"mechanism": bounded_text(mechanism.upper(), 32, "observed.smtp.auth_mechanism", audit)}
                if blob:
                    raw_blob = blob.encode("utf-8", "replace")
                    auth["credential_blob_length"] = len(raw_blob)
                    auth["credential_blob_sha256"] = hashlib.sha256(raw_blob).hexdigest()
                observed = {"smtp": {"command": "AUTH", "auth": auth}}
                attach_capture_metadata(observed, audit)
                self.emit("smtp.auth_attempt", observed, "medium")
                self.wfile.write(b"535 5.7.8 Authentication credentials invalid\r\n")
            elif verb in {"MAIL", "RCPT"}:
                value = bounded_text(argument, 512, "observed.smtp.envelope", audit)
                observed = {"smtp": {"command": verb, "envelope": value}}
                attach_capture_metadata(observed, audit)
                self.emit("smtp.envelope", observed, "low")
                self.wfile.write(b"250 2.1.0 OK\r\n")
            elif verb == "DATA":
                self.emit("smtp.command", {"smtp": {"command": "DATA"}}, "low")
                self.wfile.write(b"554 5.5.1 Message content unavailable\r\n")
            elif verb == "QUIT":
                self.emit("smtp.command", {"smtp": {"command": "QUIT"}})
                self.wfile.write(b"221 2.0.0 Bye\r\n")
                break
            else:
                value = bounded_text(line, 512, "observed.command", audit)
                observed = {"command": value, "smtp": {"command": verb}}
                attach_capture_metadata(observed, audit)
                self.emit("smtp.command", observed, "low")
                self.wfile.write(b"502 5.5.2 Command not implemented\r\n")

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.sensor.emit("connection.closed", self.observed(closed=True))
        finally:
            super().finish()


@register_sensor
class SMTPSensorPlugin:
    name = "smtp"
    capabilities = SensorCapabilities(
        protocols=("smtp", "tcp"),
        event_types=("connection", "connection.closed", "smtp.command", "smtp.auth_attempt", "smtp.envelope", "sensor.input_rejected"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
        captures_credentials=True,
        captures_commands=True,
        captures_payloads=False,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "smtp-decoy-01")[:96],
            enabled=os.getenv("AEGIS_SMTP_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_SMTP_BIND", "0.0.0.0"),
            ports={"smtp": int(os.getenv("AEGIS_SMTP_PORT", "2525"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        SMTPHandler.sensor = SensorClient(config.sensor_id)
        heartbeat = SMTPHandler.sensor.start_heartbeat()
        try:
            with BoundedThreadingTCPServer(
                (config.bind_host, config.port("smtp")),
                SMTPHandler,
                max_connections=int(config.options.get("max_connections", 32)),
            ) as server:
                server.serve_forever()
        finally:
            heartbeat.stop()


def main():
    SMTPSensorPlugin.run(SMTPSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
