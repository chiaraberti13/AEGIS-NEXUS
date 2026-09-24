import socket
import threading

import pytest

from aegis_nexus.sensors.base import SensorCapabilities, SensorConfig
from aegis_nexus.sensors.catalog import load_builtin_sensors
from aegis_nexus.sensors.legacy import LegacySensorPlugin
from aegis_nexus.sensors.mysql_decoy import (
    CLIENT_PLUGIN_AUTH,
    CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION,
    MAX_PACKET as MYSQL_MAX_PACKET,
    MySQLHandler,
    MySQLSensorPlugin,
    mysql_packet,
)
from aegis_nexus.sensors.redis_decoy import RedisHandler, RedisSensorPlugin
from aegis_nexus.sensors.registry import SensorRegistry
from aegis_nexus.sensors.server import BoundedThreadingTCPServer
from aegis_nexus.sensors.smtp_decoy import SMTPHandler, SMTPSensorPlugin
from aegis_nexus.sensors.ssh_decoy import SSHSensorPlugin
from aegis_nexus.sensors.web_decoy import WebSensorPlugin


def test_builtin_sensor_catalog_exposes_safe_capability_metadata():
    registry = load_builtin_sensors(SensorRegistry())
    registry.register(SMTPSensorPlugin)
    assert registry.names() == ("legacy", "mysql", "redis", "smtp", "ssh", "web")
    descriptions = {item["name"]: item["capabilities"] for item in registry.describe()}
    assert descriptions["ssh"]["captures_commands"] is True
    assert descriptions["web"]["captures_payloads"] is True
    assert descriptions["legacy"]["captures_credentials"] is True
    assert descriptions["redis"]["captures_payloads"] is True
    assert descriptions["mysql"]["captures_credentials"] is True
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
    monkeypatch.setenv("AEGIS_MYSQL_PORT", "3307")

    ssh = SSHSensorPlugin.config_from_env()
    web = WebSensorPlugin.config_from_env()
    legacy = LegacySensorPlugin.config_from_env()
    redis = RedisSensorPlugin.config_from_env()
    mysql = MySQLSensorPlugin.config_from_env()

    assert ssh.sensor_id == "fixture-sensor"
    assert ssh.port("ssh") == 2200
    assert ssh.options["max_connections"] == 256
    assert web.port("http") == 8088
    assert legacy.port("ftp") == 2100
    assert legacy.port("telnet") == 2300
    assert redis.port("redis") == 6380
    assert mysql.port("mysql") == 3307


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


def _mysql_exchange(monkeypatch, login_packet: bytes):
    captured = []
    monkeypatch.setattr(
        MySQLHandler.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )
    server = BoundedThreadingTCPServer(("127.0.0.1", 0), MySQLHandler, max_connections=2)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            handshake = client.recv(4096)
            client.sendall(login_packet)
            response = client.recv(4096)
        thread.join(timeout=2)
    finally:
        server.server_close()
    return handshake, response, captured


def _mysql_login(username: bytes, auth_response: bytes) -> bytes:
    flags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    payload = (
        flags.to_bytes(4, "little")
        + (16 * 1024 * 1024).to_bytes(4, "little")
        + b"\x2d"
        + (b"\x00" * 23)
        + username
        + b"\x00"
        + bytes([len(auth_response)])
        + auth_response
        + b"caching_sha2_password\x00"
    )
    return mysql_packet(payload, 1)


def test_mysql_decoy_emits_handshake_and_hashes_auth_response(monkeypatch):
    auth_response = b"0123456789abcdefghij"
    handshake, response, captured = _mysql_exchange(
        monkeypatch,
        _mysql_login(b"root", auth_response),
    )

    assert handshake[4] == 10
    assert b"8.0.36-aegis" in handshake
    assert response[4] == 0xFF

    credential = next(args[1] for args, _kwargs in captured if args[0] == "credential")
    assert credential["credential"]["username"] == "root"
    assert credential["mysql"]["auth_plugin"] == "caching_sha2_password"
    assert credential["mysql"]["auth_response_length"] == len(auth_response)
    assert len(credential["mysql"]["auth_response_sha256"]) == 64
    assert credential["mysql"]["auth_response_stored"] is False
    assert auth_response.decode() not in str(credential)
    assert MySQLSensorPlugin.capabilities.executes_attacker_input is False


def test_mysql_decoy_rejects_oversized_login_packet_before_body(monkeypatch):
    oversized_header = (MYSQL_MAX_PACKET + 1).to_bytes(3, "little") + b"\x01"
    handshake, response, captured = _mysql_exchange(monkeypatch, oversized_header)

    assert handshake[4] == 10
    assert response[4] == 0xFF
    rejected = next(args[1] for args, _kwargs in captured if args[0] == "sensor.input_rejected")
    assert rejected["sensor_capture"]["rejected"] is True
    assert rejected["sensor_capture"]["reason"] == "packet_too_large"
    assert rejected["sensor_capture"]["packet_limit"] == MYSQL_MAX_PACKET
