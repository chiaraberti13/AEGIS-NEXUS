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
from .server import BoundedThreadingTCPServer

MAX_PACKET = 16384
TIMEOUT = 20.0

CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
SERVER_CAPABILITIES = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH


class MySQLProtocolError(ValueError):
    pass


def mysql_packet(payload: bytes, sequence: int) -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("MySQL packet payload too large")
    return len(payload).to_bytes(3, "little") + bytes([sequence & 0xFF]) + payload


def read_lenenc(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise MySQLProtocolError("missing_length_encoded_integer")
    first = data[position]
    position += 1
    if first < 0xFB:
        return first, position
    if first == 0xFC:
        size = 2
    elif first == 0xFD:
        size = 3
    elif first == 0xFE:
        size = 8
    else:
        raise MySQLProtocolError("invalid_length_encoded_integer")
    end = position + size
    if end > len(data):
        raise MySQLProtocolError("truncated_length_encoded_integer")
    return int.from_bytes(data[position:end], "little"), end


def read_nul(data: bytes, position: int, field: str) -> tuple[bytes, int]:
    end = data.find(b"\x00", position)
    if end < 0:
        raise MySQLProtocolError(f"unterminated_{field}")
    return data[position:end], end + 1


class MySQLHandler(socketserver.StreamRequestHandler):
    sensor = SensorClient("mysql-decoy-01")

    def setup(self):
        super().setup()
        self.request.settimeout(TIMEOUT)
        self.sensor_session_id = uuid.uuid4().hex
        self.connection_started = time.monotonic()
        self.challenge = os.urandom(20)

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
            "service": "mysql",
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

    def send(self, payload: bytes, sequence: int) -> None:
        self.wfile.write(mysql_packet(payload, sequence))
        self.wfile.flush()

    def handshake(self) -> bytes:
        lower = SERVER_CAPABILITIES & 0xFFFF
        upper = (SERVER_CAPABILITIES >> 16) & 0xFFFF
        return (
            b"\x0a"
            + b"8.0.36-aegis\x00"
            + (1337).to_bytes(4, "little")
            + self.challenge[:8]
            + b"\x00"
            + lower.to_bytes(2, "little")
            + b"\x2d"
            + (2).to_bytes(2, "little")
            + upper.to_bytes(2, "little")
            + b"\x15"
            + (b"\x00" * 10)
            + self.challenge[8:]
            + b"\x00"
            + b"caching_sha2_password\x00"
        )

    def read_login_packet(self) -> bytes:
        header = self.rfile.read(4)
        if not header:
            raise EOFError
        if len(header) != 4:
            raise MySQLProtocolError("truncated_packet_header")
        length = int.from_bytes(header[:3], "little")
        if length < 32:
            raise MySQLProtocolError("login_packet_too_short")
        if length > MAX_PACKET:
            raise MySQLProtocolError("packet_too_large")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise MySQLProtocolError("truncated_packet")
        return payload

    def parse_login(self, payload: bytes) -> dict:
        if len(payload) < 32:
            raise MySQLProtocolError("login_packet_too_short")
        flags = int.from_bytes(payload[0:4], "little")
        max_packet = int.from_bytes(payload[4:8], "little")
        charset = payload[8]
        position = 32
        username_raw, position = read_nul(payload, position, "username")

        auth = b""
        if flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            auth_length, position = read_lenenc(payload, position)
            if auth_length > MAX_PACKET or position + auth_length > len(payload):
                raise MySQLProtocolError("invalid_auth_response_length")
            auth = payload[position : position + auth_length]
            position += auth_length
        elif flags & CLIENT_SECURE_CONNECTION:
            if position >= len(payload):
                raise MySQLProtocolError("missing_auth_response_length")
            auth_length = payload[position]
            position += 1
            if position + auth_length > len(payload):
                raise MySQLProtocolError("truncated_auth_response")
            auth = payload[position : position + auth_length]
            position += auth_length
        else:
            auth, position = read_nul(payload, position, "auth_response")

        audit: dict = {}
        username = bounded_text(
            username_raw.decode("utf-8", "replace"),
            128,
            "observed.credential.username",
            audit,
        )
        mysql = {
            "client_capabilities": f"0x{flags:08x}",
            "client_max_packet": max_packet,
            "client_charset": charset,
            "auth_response_length": len(auth),
            "auth_response_sha256": hashlib.sha256(auth).hexdigest(),
            "auth_response_stored": False,
        }

        if flags & CLIENT_CONNECT_WITH_DB and position < len(payload):
            database_raw, position = read_nul(payload, position, "database")
            mysql["database"] = bounded_text(
                database_raw.decode("utf-8", "replace"),
                128,
                "observed.mysql.database",
                audit,
            )

        if flags & CLIENT_PLUGIN_AUTH and position < len(payload):
            plugin_raw, _ = read_nul(payload, position, "auth_plugin")
            mysql["auth_plugin"] = bounded_text(
                plugin_raw.decode("ascii", "replace"),
                64,
                "observed.mysql.auth_plugin",
                audit,
            )

        observed = {
            "credential": {"username": username},
            "mysql": mysql,
        }
        attach_capture_metadata(observed, audit)
        return observed

    def reject(self, reason: str) -> None:
        self.emit(
            "sensor.input_rejected",
            {
                "sensor_capture": {
                    "rejected": True,
                    "path": "observed.mysql_login_packet",
                    "reason": reason,
                    "packet_limit": MAX_PACKET,
                }
            },
            "low",
        )

    def access_denied(self, username: str) -> bytes:
        safe = username.replace("\x00", "")[:64]
        message = f"Access denied for user '{safe}' (using password: YES)".encode("utf-8", "replace")
        return b"\xff" + (1045).to_bytes(2, "little") + b"#28000" + message

    def handle(self):
        self.emit("connection")
        self.send(self.handshake(), 0)
        try:
            payload = self.read_login_packet()
            observed = self.parse_login(payload)
        except EOFError:
            return
        except MySQLProtocolError as exc:
            self.reject(str(exc))
            self.send(b"\xff" + (1156).to_bytes(2, "little") + b"#08S01Malformed handshake response", 2)
            return

        self.emit("credential", observed, "medium")
        self.send(self.access_denied(observed["credential"]["username"]), 2)

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.sensor.emit("connection.closed", self.observed(closed=True))
        finally:
            super().finish()


@register_sensor
class MySQLSensorPlugin:
    name = "mysql"
    capabilities = SensorCapabilities(
        protocols=("mysql", "tcp"),
        event_types=("connection", "connection.closed", "credential", "sensor.input_rejected"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
        captures_credentials=True,
        captures_commands=False,
        captures_payloads=False,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "mysql-decoy-01")[:96],
            enabled=os.getenv("AEGIS_MYSQL_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_MYSQL_BIND", "0.0.0.0"),
            ports={"mysql": int(os.getenv("AEGIS_MYSQL_PORT", "3306"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        MySQLHandler.sensor = SensorClient(config.sensor_id)
        with BoundedThreadingTCPServer(
            (config.bind_host, config.port("mysql")),
            MySQLHandler,
            max_connections=int(config.options.get("max_connections", 32)),
        ) as server:
            server.serve_forever()


def main():
    MySQLSensorPlugin.run(MySQLSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
