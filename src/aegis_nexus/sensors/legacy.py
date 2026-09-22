from __future__ import annotations

import os
import socketserver
import threading
from typing import BinaryIO

from .client import SensorClient

MAX_LINE = 512
TIMEOUT = 15.0


def _readline(stream: BinaryIO) -> str:
    data = stream.readline(MAX_LINE + 1)
    if len(data) > MAX_LINE:
        return ""
    return data.decode("utf-8", "replace").strip()


class BaseHandler(socketserver.StreamRequestHandler):
    service = "legacy"
    sensor = SensorClient("legacy-01")

    def setup(self):
        super().setup()
        self.request.settimeout(TIMEOUT)

    @property
    def source_ip(self) -> str:
        return str(self.client_address[0])

    @property
    def destination_port(self) -> int:
        return int(self.server.server_address[1])

    def emit(self, event_type: str, observed: dict, severity: str = "info"):
        base = {"source_ip": self.source_ip, "service": self.service, "protocol": "tcp", **observed}
        self.sensor.emit(event_type, base, severity)


class FTPHandler(BaseHandler):
    service = "ftp"

    def handle(self):
        self.emit("connection", {"destination_port": self.destination_port})
        self.wfile.write(b"220 Meridian FTP Service\r\n")
        username = ""
        for _ in range(6):
            line = _readline(self.rfile)
            if not line:
                break
            command, _, argument = line.partition(" ")
            command = command.upper()
            if command == "USER":
                username = argument[:128]
                self.wfile.write(b"331 Password required\r\n")
            elif command == "PASS":
                self.emit("credential", {"destination_port": self.destination_port, "credential": {"username": username, "password": argument[:256]}}, "medium")
                self.wfile.write(b"530 Login incorrect\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 Goodbye\r\n")
                break
            else:
                self.emit("legacy.command", {"destination_port": self.destination_port, "command": line[:256]}, "low")
                self.wfile.write(b"500 Command not understood\r\n")


class TelnetHandler(BaseHandler):
    service = "telnet"

    def handle(self):
        self.emit("connection", {"destination_port": self.destination_port})
        self.wfile.write(b"Meridian Gateway\r\nlogin: ")
        username = _readline(self.rfile)[:128]
        self.wfile.write(b"Password: ")
        password = _readline(self.rfile)[:256]
        self.emit("credential", {"destination_port": self.destination_port, "credential": {"username": username, "password": password}}, "medium")
        self.wfile.write(b"Login incorrect\r\n")


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = "0.0.0.0"
    ftp_port = int(os.getenv("AEGIS_FTP_PORT", "2121"))
    telnet_port = int(os.getenv("AEGIS_TELNET_PORT", "2323"))
    FTPHandler.sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "legacy-01"))
    TelnetHandler.sensor = FTPHandler.sensor
    ftp = ThreadingServer((host, ftp_port), FTPHandler)
    telnet = ThreadingServer((host, telnet_port), TelnetHandler)
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
