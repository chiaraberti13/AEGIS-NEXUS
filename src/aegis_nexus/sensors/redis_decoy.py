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

MAX_LINE = 1024
MAX_BULK = 4096
MAX_ARGS = 16
MAX_COMMANDS = 64
TIMEOUT = 20.0


class RedisProtocolError(ValueError):
    pass


class RedisHandler(socketserver.StreamRequestHandler):
    sensor = SensorClient("redis-decoy-01")

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
            "service": "redis",
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

    def reject(self, reason: str, *, observed_at_least: int | None = None) -> None:
        capture = {
            "rejected": True,
            "path": "observed.redis_command",
            "reason": reason,
            "line_limit": MAX_LINE,
            "bulk_limit": MAX_BULK,
            "argument_limit": MAX_ARGS,
        }
        if observed_at_least is not None:
            capture["bytes_observed_at_least"] = observed_at_least
        self.emit("sensor.input_rejected", {"sensor_capture": capture}, "low")

    def read_line(self) -> bytes:
        raw = self.rfile.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            raise RedisProtocolError("line_too_long")
        if not raw:
            raise EOFError
        if not raw.endswith(b"\n"):
            raise RedisProtocolError("unterminated_line")
        return raw.rstrip(b"\r\n")

    def read_bulk(self, length: int) -> bytes:
        if length < 0:
            return b""
        if length > MAX_BULK:
            raise RedisProtocolError("bulk_too_large")
        data = self.rfile.read(length)
        ending = self.rfile.read(2)
        if len(data) != length or ending != b"\r\n":
            raise RedisProtocolError("invalid_bulk")
        return data

    def read_command(self) -> list[bytes]:
        first = self.read_line()
        if first.startswith(b"*"):
            try:
                count = int(first[1:])
            except ValueError as exc:
                raise RedisProtocolError("invalid_array_length") from exc
            if count < 1 or count > MAX_ARGS:
                raise RedisProtocolError("argument_limit")
            args: list[bytes] = []
            for _ in range(count):
                header = self.read_line()
                if not header.startswith(b"$"):
                    raise RedisProtocolError("bulk_string_required")
                try:
                    length = int(header[1:])
                except ValueError as exc:
                    raise RedisProtocolError("invalid_bulk_length") from exc
                args.append(self.read_bulk(length))
            return args

        if len(first) > MAX_LINE:
            raise RedisProtocolError("line_too_long")
        args = first.split()
        if not args or len(args) > MAX_ARGS:
            raise RedisProtocolError("argument_limit")
        if any(len(item) > MAX_BULK for item in args):
            raise RedisProtocolError("bulk_too_large")
        return args

    @staticmethod
    def text(value: bytes, limit: int, path: str, audit: dict) -> str:
        return bounded_text(value.decode("utf-8", "replace"), limit, path, audit)

    def command_evidence(self, args: list[bytes]) -> tuple[str, dict]:
        audit: dict = {}
        command = self.text(args[0], 32, "observed.redis.command", audit).upper()
        redis: dict = {"command": command, "argument_count": max(0, len(args) - 1)}

        if command == "AUTH" and len(args) >= 2:
            if len(args) >= 3:
                redis["username"] = self.text(args[-2], 128, "observed.redis.username", audit)
            secret = args[-1]
            redis["credential_secret_length"] = len(secret)
            redis["credential_secret_sha256"] = hashlib.sha256(secret).hexdigest()
        elif command in {"GET", "SET", "DEL", "EXISTS", "HGET", "HSET"} and len(args) >= 2:
            redis["key"] = self.text(args[1], 256, "observed.redis.key", audit)
            if command in {"SET", "HSET"} and len(args) >= 3:
                payload = b"\x00".join(args[2:])
                redis["payload_length"] = len(payload)
                redis["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        elif len(args) > 1:
            redis["arguments_sha256"] = hashlib.sha256(b"\x00".join(args[1:])).hexdigest()
            redis["arguments_bytes"] = sum(len(item) for item in args[1:])

        observed = {"redis": redis}
        attach_capture_metadata(observed, audit)
        return command, observed

    def handle_command(self, args: list[bytes]) -> bool:
        command, observed = self.command_evidence(args)
        if command == "AUTH":
            self.emit("redis.auth_attempt", observed, "medium")
            self.wfile.write(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
        else:
            self.emit("redis.command", observed, "low")
            if command == "PING":
                self.wfile.write(b"+PONG\r\n")
            elif command == "ECHO" and len(args) >= 2:
                value = args[1][:256]
                self.wfile.write(b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n")
            elif command == "INFO":
                body = b"# Server\r\nredis_version:7.2.0\r\nredis_mode:standalone\r\n"
                self.wfile.write(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
            elif command in {"SET", "SELECT"}:
                self.wfile.write(b"+OK\r\n")
            elif command in {"GET", "HGET"}:
                self.wfile.write(b"$-1\r\n")
            elif command in {"DEL", "EXISTS"}:
                self.wfile.write(b":0\r\n")
            elif command == "QUIT":
                self.wfile.write(b"+OK\r\n")
                return False
            else:
                self.wfile.write(b"-ERR command not available in emulated service\r\n")
        return True

    def handle(self):
        self.emit("connection")
        for _ in range(MAX_COMMANDS):
            try:
                args = self.read_command()
            except EOFError:
                break
            except RedisProtocolError as exc:
                self.reject(str(exc))
                self.wfile.write(b"-ERR protocol error\r\n")
                break
            if not self.handle_command(args):
                break

    def finish(self):
        try:
            if hasattr(self, "connection_started"):
                self.sensor.emit("connection.closed", self.observed(closed=True))
        finally:
            super().finish()


@register_sensor
class RedisSensorPlugin:
    name = "redis"
    capabilities = SensorCapabilities(
        protocols=("redis", "tcp"),
        event_types=("connection", "connection.closed", "redis.command", "redis.auth_attempt", "sensor.input_rejected"),
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
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "redis-decoy-01")[:96],
            enabled=os.getenv("AEGIS_REDIS_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_REDIS_BIND", "0.0.0.0"),
            ports={"redis": int(os.getenv("AEGIS_REDIS_PORT", "6379"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        RedisHandler.sensor = SensorClient(config.sensor_id)
        heartbeat = RedisHandler.sensor.start_heartbeat()
        try:
            with BoundedThreadingTCPServer(
                (config.bind_host, config.port("redis")),
                RedisHandler,
                max_connections=int(config.options.get("max_connections", 32)),
            ) as server:
                server.serve_forever()
        finally:
            heartbeat.stop()


def main():
    RedisSensorPlugin.run(RedisSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
