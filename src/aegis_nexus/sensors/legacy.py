from __future__ import annotations

import os
import socketserver
import threading
import uuid
from typing import BinaryIO

from .capture import attach_capture_metadata, bounded_text
from .client import SensorClient
from .server import BoundedThreadingTCPServer

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

    @property
    def source_ip(self) -> str:
        return str(self.client_address[0])

    @property
    def destination_port(self) -> int:
        return int(self.server.server_address[1])

    def emit(self, event_type: str, observed: dict, severity: str = "info"):
        base = {
            "source_ip": self.source_ip,
            "service": self.service,
            "protocol": "tcp",
            "sensor_session_id": self.sensor_session_id,
            **observed,
        }
        self.sensor.emit(event_type, base, severity)

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


def main():
    host = "0.0.0.0"
    ftp_port = int(os.getenv("AEGIS_FTP_PORT", "2121"))
    telnet_port = int(os.getenv("AEGIS_TELNET_PORT", "2323"))
    max_connections = int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32"))
    FTPHandler.sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "legacy-01"))
    TelnetHandler.sensor = FTPHandler.sensor
    ftp = BoundedThreadingTCPServer((host, ftp_port), FTPHandler, max_connections=max_connections)
    telnet = BoundedThreadingTCPServer((host, telnet_port), TelnetHandler, max_connections=max_connections)
    threads = [
        threading.Thread(target=ftp.serve_forever, daemon=True),
        threading.Thread(target=telnet.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
