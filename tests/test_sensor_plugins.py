import socket
import threading

import pytest

from aegis_nexus.sensors.base import SensorCapabilities, SensorConfig
from aegis_nexus.sensors.catalog import load_builtin_sensors
from aegis_nexus.sensors.legacy import LegacySensorPlugin
from aegis_nexus.sensors.redis_decoy import RedisHandler, RedisSensorPlugin
from aegis_nexus.sensors.registry import SensorRegistry
from aegis_nexus.sensors.server import BoundedThreadingTCPServer
from aegis_nexus.sensors.smtp_decoy import SMTPHandler, SMTPSensorPlugin
from aegis_nexus.sensors.ssh_decoy import SSHSensorPlugin
from aegis_nexus.sensors.web_decoy import WebSensorPlugin


def test_builtin_sensor_catalog_exposes_safe_capability_metadata():
    registry = load_builtin_sensors(SensorRegistry())
    registry.register(SMTPSensorPlugin)
    assert registry.names() == ("legacy", "redis", "smtp", "ssh", "web")
    descriptions = {item["name"]: item["capabilities"] for item in registry.describe()}
    assert descriptions["ssh"]["captures_commands"] is True
    assert descriptions["web"]["captures_payloads"] is True
    assert descriptions["legacy"]["captures_credentials"] is True
    assert descriptions["redis"]["captures_payloads"] is True
    assert all(item["executes_attacker_input"] is False for item in descriptions.values())


def test_sensor_registry_rejects_duplicate_names_and_unsafe_capabilities():
    registry = SensorRegistry()

    class First:
        name = "fixture"
        capabilities = SensorCapabilities(protocols=("tcp",), event_types=("connection",))

    class Duplicate:
        name = "fixture"
        capabilities = SensorCapabilities(protocols=("tcp",), event_types=("connection",))

    registry.register(First)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(Duplicate)

    class Unsafe:
        name = "unsafe"
        capabilities = SensorCapabilities(
            protocols=("tcp",),
            event_types=("command",),
            executes_attacker_input=True,
        )

    with pytest.raises(ValueError, match="must not execute"):
        registry.register(Unsafe)


def test_declarative_sensor_configs_are_bounded_and_protocol_specific(monkeypatch):
    monkeypatch.setenv("AEGIS_HONEYPOT_ID", "fixture-sensor")
    monkeypatch.setenv("AEGIS_SENSOR_MAX_CONNECTIONS", "9999")
    monkeypatch.setenv("AEGIS_SSH_PORT", "2200")
    monkeypatch.setenv("AEGIS_WEB_PORT", "8088")
    monkeypatch.setenv("AEGIS_FTP_PORT", "2100")
    monkeypatch.setenv("AEGIS_TELNET_PORT", "2300")
    monkeypatch.setenv("AEGIS_REDIS_PORT", "6380")

    ssh = SSHSensorPlugin.config_from_env()
    web = WebSensorPlugin.config_from_env()
    legacy = LegacySensorPlugin.config_from_env()
    redis = RedisSensorPlugin.config_from_env()

    assert ssh.sensor_id == "fixture-sensor"
    assert ssh.port("ssh") == 2200
    assert ssh.options["max_connections"] == 256
    assert web.port("http") == 8088
    assert legacy.port("ftp") == 2100
    assert legacy.port("telnet") == 2300
    assert redis.port("redis") == 6380


def test_sensor_config_rejects_invalid_listener_port():
    config = SensorConfig(sensor_id="fixture", ports={"tcp": 70000})
    with pytest.raises(ValueError, match="invalid sensor port"):
        config.port("tcp")


def test_smtp_decoy_hashes_auth_blob_and_never_executes_input(monkeypatch):
    captured = []
    monkeypatch.setattr(
        SMTPHandler.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )
    server = BoundedThreadingTCPServer(("127.0.0.1", 0), SMTPHandler, max_connections=2)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            banner = client.recv(1024)
            assert banner.startswith(b"220 ")
            client.sendall(b"AUTH PLAIN dXNlcgB1c2VyAHNlY3JldA==\r\n")
            response = client.recv(1024)
            assert response.startswith(b"535 ")
        thread.join(timeout=2)
    finally:
        server.server_close()

    auth = next(args[1] for args, _kwargs in captured if args[0] == "smtp.auth_attempt")
    evidence = auth["smtp"]["auth"]
    assert evidence["mechanism"] == "PLAIN"
    assert evidence["credential_blob_length"] > 0
    assert len(evidence["credential_blob_sha256"]) == 64
    assert "dXNlcgB1c2VyAHNlY3JldA==" not in str(auth)
    assert SMTPSensorPlugin.capabilities.executes_attacker_input is False


def _redis_exchange(monkeypatch, payload: bytes):
    captured = []
    monkeypatch.setattr(
        RedisHandler.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )
    server = BoundedThreadingTCPServer(("127.0.0.1", 0), RedisHandler, max_connections=2)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.sendall(payload)
            response = client.recv(4096)
        thread.join(timeout=2)
    finally:
        server.server_close()
    return response, captured


def test_redis_decoy_supports_resp_ping_without_executing_input(monkeypatch):
    response, captured = _redis_exchange(monkeypatch, b"*1\r\n$4\r\nPING\r\n")
    assert response == b"+PONG\r\n"
    command = next(args[1] for args, _kwargs in captured if args[0] == "redis.command")
    assert command["redis"]["command"] == "PING"
    assert command["service"] == "redis"
    assert command["network"]["source"] == "sensor_socket"
    assert RedisSensorPlugin.capabilities.executes_attacker_input is False


def test_redis_auth_secret_is_hashed_and_not_stored(monkeypatch):
    secret = b"super-secret-password"
    payload = b"*2\r\n$4\r\nAUTH\r\n$" + str(len(secret)).encode() + b"\r\n" + secret + b"\r\n"
    response, captured = _redis_exchange(monkeypatch, payload)
    assert response.startswith(b"-WRONGPASS ")
    auth = next(args[1] for args, _kwargs in captured if args[0] == "redis.auth_attempt")
    evidence = auth["redis"]
    assert evidence["credential_secret_length"] == len(secret)
    assert len(evidence["credential_secret_sha256"]) == 64
    assert secret.decode() not in str(auth)


def test_redis_set_payload_is_fingerprinted_not_retained(monkeypatch):
    value = b"attacker-controlled-payload"
    payload = (
        b"*3\r\n$3\r\nSET\r\n$6\r\ntarget\r\n$"
        + str(len(value)).encode()
        + b"\r\n"
        + value
        + b"\r\n"
    )
    response, captured = _redis_exchange(monkeypatch, payload)
    assert response == b"+OK\r\n"
    event = next(args[1] for args, _kwargs in captured if args[0] == "redis.command")
    assert event["redis"]["key"] == "target"
    assert event["redis"]["payload_length"] == len(value)
    assert len(event["redis"]["payload_sha256"]) == 64
    assert value.decode() not in str(event)


def test_redis_rejects_oversized_bulk_input(monkeypatch):
    response, captured = _redis_exchange(monkeypatch, b"*2\r\n$3\r\nSET\r\n$5000\r\n")
    assert response == b"-ERR protocol error\r\n"
    rejected = next(args[1] for args, _kwargs in captured if args[0] == "sensor.input_rejected")
    assert rejected["sensor_capture"]["rejected"] is True
    assert rejected["sensor_capture"]["reason"] == "bulk_too_large"
