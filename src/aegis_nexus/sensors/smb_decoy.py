from __future__ import annotations

import hashlib
import os
import socketserver
import struct
import time
import uuid

from ..network_evidence import make_network_evidence
from .base import SensorCapabilities, SensorConfig
from .client import SensorClient
from .registry import register_sensor
from .server import BoundedThreadingTCPServer

MAX_FRAME = 65536
TIMEOUT = 20.0
SMB2_PROTOCOL = b"\xfeSMB"
SMB2_HEADER_SIZE = 64
SMB2_NEGOTIATE = 0
SMB2_SESSION_SETUP = 1
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_NOT_SUPPORTED = 0xC00000BB
SUPPORTED_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)


class SMBProtocolError(ValueError):
    pass


def netbios_frame(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("SMB frame too large")
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb2_header(request: bytes, *, status: int, command: int, credits: int = 1) -> bytes:
    message_id = request[24:32] if len(request) >= SMB2_HEADER_SIZE else b"\x00" * 8
    return (
        SMB2_PROTOCOL
        + struct.pack("<H", SMB2_HEADER_SIZE)
        + b"\x00\x00"
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", max(1, min(credits, 256)))
        + struct.pack("<I", 0x00000001)
        + b"\x00" * 4
        + message_id
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )


def parse_negotiate(payload: bytes) -> dict:
    if len(payload) < SMB2_HEADER_SIZE + 36:
        raise SMBProtocolError("negotiate_too_short")
    body = payload[SMB2_HEADER_SIZE:]
    if int.from_bytes(body[0:2], "little") != 36:
        raise SMBProtocolError("invalid_negotiate_structure")
    dialect_count = int.from_bytes(body[2:4], "little")
    if dialect_count < 1 or dialect_count > 64:
        raise SMBProtocolError("invalid_dialect_count")
    dialect_end = SMB2_HEADER_SIZE + 36 + dialect_count * 2
    if dialect_end > len(payload):
        raise SMBProtocolError("truncated_dialects")
    dialects = [
        int.from_bytes(payload[offset : offset + 2], "little")
        for offset in range(SMB2_HEADER_SIZE + 36, dialect_end, 2)
    ]
    return {
        "security_mode": int.from_bytes(body[4:6], "little"),
        "capabilities": int.from_bytes(body[8:12], "little"),
        "client_guid": body[12:28].hex(),
        "dialects": [f"0x{value:04x}" for value in dialects],
        "_dialect_values": dialects,
    }


def parse_session_setup(payload: bytes) -> dict:
    if len(payload) < SMB2_HEADER_SIZE + 24:
        raise SMBProtocolError("session_setup_too_short")
    body = payload[SMB2_HEADER_SIZE:]
    if int.from_bytes(body[0:2], "little") != 25:
        raise SMBProtocolError("invalid_session_setup_structure")
    security_offset = int.from_bytes(body[12:14], "little")
    security_length = int.from_bytes(body[14:16], "little")
    if security_length > MAX_FRAME:
        raise SMBProtocolError("security_blob_too_large")
    end = security_offset + security_length
    if security_offset < SMB2_HEADER_SIZE or end > len(payload):
        raise SMBProtocolError("invalid_security_buffer")
    blob = payload[security_offset:end]
    return {
        "security_mode": body[3],
        "capabilities": int.from_bytes(body[4:8], "little"),
        "security_blob_length": len(blob),
        "security_blob_sha256": hashlib.sha256(blob).hexdigest(),
        "security_blob_stored": False,
        "auth_mechanism": "ntlmssp" if b"NTLMSSP\x00" in blob else "opaque",
    }


class SMBHandler(socketserver.StreamRequestHandler):
    sensor = SensorClient("smb-decoy-01")

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
            "service": "smb",
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

    def reject(self, reason: str) -> None:
        self.emit(
            "sensor.input_rejected",
            {
                "sensor_capture": {
                    "rejected": True,
                    "path": "observed.smb_frame",
                    "reason": reason,
                    "frame_limit": MAX_FRAME,
                }
            },
            "low",
        )

    def read_frame(self) -> bytes:
        header = self.rfile.read(4)
        if not header:
            raise EOFError
        if len(header) != 4 or header[0] != 0:
            raise SMBProtocolError("invalid_netbios_header")
        length = int.from_bytes(header[1:4], "big")
        if length < SMB2_HEADER_SIZE:
            raise SMBProtocolError("frame_too_short")
        if length > MAX_FRAME:
            raise SMBProtocolError("frame_too_large")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise SMBProtocolError("truncated_frame")
        if payload[:4] != SMB2_PROTOCOL:
            raise SMBProtocolError("unsupported_smb_protocol")
        if int.from_bytes(payload[4:6], "little") != SMB2_HEADER_SIZE:
            raise SMBProtocolError("invalid_smb2_header")
        return payload

    def send(self, payload: bytes) -> None:
        self.wfile.write(netbios_frame(payload))
        self.wfile.flush()

    def negotiate_response(self, request: bytes, dialect: int) -> bytes:
        body = (
            struct.pack("<H", 65)
            + struct.pack("<H", 1)
            + struct.pack("<H", dialect)
            + b"\x00\x00"
            + uuid.uuid4().bytes
            + b"\x00" * 4
            + struct.pack("<I", MAX_FRAME)
            + struct.pack("<I", MAX_FRAME)
            + struct.pack("<I", MAX_FRAME)
            + b"\x00" * 8
            + b"\x00" * 8
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\x00" * 4
        )
        return smb2_header(request, status=STATUS_SUCCESS, command=SMB2_NEGOTIATE) + body

    def handle(self):
        self.emit("connection")
        for _ in range(4):
            try:
                payload = self.read_frame()
            except EOFError:
                break
            except SMBProtocolError as exc:
                self.reject(str(exc))
                break

            command = int.from_bytes(payload[12:14], "little")
            if command == SMB2_NEGOTIATE:
                try:
                    smb = parse_negotiate(payload)
                except SMBProtocolError as exc:
                    self.reject(str(exc))
                    break
                offered = smb.pop("_dialect_values")
                selected = max((d for d in offered if d in SUPPORTED_DIALECTS), default=None)
                smb["selected_dialect"] = f"0x{selected:04x}" if selected is not None else None
                self.emit("smb.negotiate", {"smb": smb}, "low")
                if selected is None:
                    self.send(smb2_header(payload, status=STATUS_NOT_SUPPORTED, command=SMB2_NEGOTIATE))
                    break
                self.send(self.negotiate_response(payload, selected))
                continue

            if command == SMB2_SESSION_SETUP:
                try:
                    smb = parse_session_setup(payload)
                except SMBProtocolError as exc:
                    self.reject(str(exc))
                    break
                self.emit("smb.auth_attempt", {"smb": smb}, "medium")
                self.send(smb2_header(payload, status=STATUS_ACCESS_DENIED, command=SMB2_SESSION_SETUP))
                break

            self.emit("smb.command", {"smb": {"command": command}}, "low")
            self.send(smb2_header(payload, status=STATUS_NOT_SUPPORTED, command=command))
            break

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.sensor.emit("connection.closed", self.observed(closed=True))
        finally:
            super().finish()


@register_sensor
class SMBSensorPlugin:
    name = "smb"
    capabilities = SensorCapabilities(
        protocols=("smb2", "tcp"),
        event_types=(
            "connection",
            "connection.closed",
            "smb.negotiate",
            "smb.auth_attempt",
            "smb.command",
            "sensor.input_rejected",
        ),
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
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "smb-decoy-01")[:96],
            enabled=os.getenv("AEGIS_SMB_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_SMB_BIND", "0.0.0.0"),
            ports={"smb": int(os.getenv("AEGIS_SMB_PORT", "445"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        SMBHandler.sensor = SensorClient(config.sensor_id)
        heartbeat = SMBHandler.sensor.start_heartbeat()
        try:
            with BoundedThreadingTCPServer(
                (config.bind_host, config.port("smb")),
                SMBHandler,
                max_connections=int(config.options.get("max_connections", 32)),
            ) as server:
                server.serve_forever()
        finally:
            heartbeat.stop()


def main():
    SMBSensorPlugin.run(SMBSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
