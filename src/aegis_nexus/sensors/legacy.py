from __future__ import annotations

import os
import socketserver
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import BinaryIO

from .base import SensorCapabilities, SensorConfig
from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient
from ..network_evidence import make_network_evidence
from .server import BoundedThreadingTCPServer
from .registry import register_sensor
from .persona import load_persona

MAX_LINE = 512
TIMEOUT = 15.0
FTP_UPLOAD_MAX_BYTES = max(1024, min(int(os.getenv("AEGIS_QUARANTINE_MAX_BYTES", "262144")), 16 * 1024 * 1024))
PERSONA = load_persona()


class FTPDataBroker:
    def __init__(self):
        self._condition = threading.Condition()
        self._items = defaultdict(lambda: deque(maxlen=4))

    def put(self, source_ip: str, data: bytes, too_large: bool) -> None:
        with self._condition:
            self._items[source_ip].append((data, too_large))
            self._condition.notify_all()

    def take(self, source_ip: str, timeout: float = 10.0) -> tuple[bytes, bool] | None:
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._items[source_ip]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)
            return self._items[source_ip].popleft()


FTP_DATA_BROKER = FTPDataBroker()


class FTPDataHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        payload = bytearray()
        too_large = False
        try:
            while len(payload) <= FTP_UPLOAD_MAX_BYTES:
                chunk = self.request.recv(min(65536, FTP_UPLOAD_MAX_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > FTP_UPLOAD_MAX_BYTES:
                    too_large = True
                    break
        except (TimeoutError, OSError):
            pass
        FTP_DATA_BROKER.put(str(self.client_address[0]), bytes(payload[:FTP_UPLOAD_MAX_BYTES]), too_large)



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
    data_port = int(os.getenv("AEGIS_FTP_DATA_PORT", "2122"))

    def handle(self):
        self.emit("connection", {"destination_port": self.destination_port})
        self.wfile.write(f"220 {PERSONA.ftp_banner}\r\n".encode("utf-8", "replace"))
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
            elif command == "EPSV":
                self.wfile.write(f"229 Entering Extended Passive Mode (|||{self.data_port}|)\r\n".encode("ascii"))
            elif command == "PASV":
                self.wfile.write(b"522 Use EPSV for passive transfers\r\n")
            elif command == "PORT":
                self.wfile.write(b"502 Active mode disabled\r\n")
            elif command == "STOR":
                filename_audit: dict = {}
                filename = bounded_text(argument, 255, "observed.artifact.original_name", filename_audit)
                self.wfile.write(b"150 Opening passive data connection\r\n")
                transfer = FTP_DATA_BROKER.take(self.source_ip)
                if transfer is None:
                    self.emit(
                        "ftp.upload_rejected",
                        {"destination_port": self.destination_port, "artifact": {"original_name": filename, "reason": "data_timeout"}},
                        "low",
                    )
                    self.wfile.write(b"425 Data connection timed out\r\n")
                    continue
                data, too_large = transfer
                if too_large:
                    self.emit(
                        "ftp.upload_rejected",
                        {
                            "destination_port": self.destination_port,
                            "artifact": {
                                "original_name": filename,
                                "bytes_observed_at_least": FTP_UPLOAD_MAX_BYTES + 1,
                                "limit": FTP_UPLOAD_MAX_BYTES,
                                "quarantined": False,
                            },
                        },
                        "medium",
                    )
                    self.wfile.write(b"552 Transfer exceeds quarantine limit\r\n")
                    continue
                artifact = self.sensor.quarantine_artifact(
                    data,
                    original_name=filename,
                    content_type="application/octet-stream",
                )
                if artifact is None:
                    self.emit(
                        "ftp.upload_rejected",
                        {"destination_port": self.destination_port, "artifact": {"original_name": filename, "reason": "quarantine_unavailable"}},
                        "medium",
                    )
                    self.wfile.write(b"451 Transfer unavailable\r\n")
                    continue
                observed = {
                    "destination_port": self.destination_port,
                    "artifact": {
                        "artifact_id": artifact.get("artifact_id"),
                        "sha256": artifact.get("sha256"),
                        "size": artifact.get("size"),
                        "original_name": artifact.get("original_name"),
                        "content_type": artifact.get("content_type"),
                        "quarantined": True,
                        "inline_serving": False,
                        "transfer_correlation": {
                            "method": "source_ip_fifo",
                            "strength": "heuristic",
                            "basis": ["control_source_ip", "data_source_ip"],
                        },
                    },
                }
                attach_capture_metadata(observed, filename_audit)
                self.emit("artifact.quarantined", observed, "medium")
                self.wfile.write(b"226 Transfer complete\r\n")
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
        self.wfile.write(f"{PERSONA.telnet_banner}\r\nlogin: ".encode("utf-8", "replace"))
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
        event_types=("connection", "connection.closed", "credential", "legacy.command", "artifact.quarantined", "ftp.upload_rejected", "sensor.input_rejected"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
        captures_credentials=True,
        captures_commands=True,
        captures_payloads=True,
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
                "ftp_data": int(os.getenv("AEGIS_FTP_DATA_PORT", "2122")),
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
        FTPHandler.data_port = config.port("ftp_data")
        ftp_data = BoundedThreadingTCPServer(
            (config.bind_host, config.port("ftp_data")),
            FTPDataHandler,
            max_connections=max_connections,
        )
        threads = [
            threading.Thread(target=ftp.serve_forever, daemon=True),
            threading.Thread(target=telnet.serve_forever, daemon=True),
            threading.Thread(target=ftp_data.serve_forever, daemon=True),
        ]
        heartbeat = FTPHandler.sensor.start_heartbeat()
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            heartbeat.stop()
            ftp.server_close()
            telnet.server_close()
            ftp_data.server_close()


def main():
    LegacySensorPlugin.run(LegacySensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
