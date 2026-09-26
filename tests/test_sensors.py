import hashlib
import io
import socket
import threading

from aegis_nexus.sensors.legacy import FTPDataHandler, FTPHandler, _readline, _readline_with_status
from aegis_nexus.sensors.server import BoundedThreadingTCPServer
from aegis_nexus.sensors.ssh_decoy import PERSONA as SSH_PERSONA, _base_observed, _fake_command, _read_command
from aegis_nexus.sensors import web_decoy


def test_ssh_commands_are_emulated_not_executed():
    assert _fake_command("whoami") == f"{SSH_PERSONA.username}\n"
    assert "command not found" in _fake_command("curl http://example.invalid/payload")
    assert _fake_command("cat /etc/hostname") == f"{SSH_PERSONA.hostname}\n"


def test_legacy_reader_rejects_oversized_line():
    assert _readline(io.BytesIO(b"A" * 600 + b"\n")) == ""


def test_web_decoy_captures_credentials_without_authenticating(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    response = client.post("/login", data={"username": "root", "password": "toor"})
    assert response.status_code == 401
    assert captured
    observed = captured[0][0][1]
    assert observed["credential"]["username"] == "root"
    assert observed["credential"]["password"] == "toor"


def test_web_decoy_flags_pattern_without_claiming_cve(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    response = client.get("/viewer?doc=../../etc/passwd")
    assert response.status_code == 200
    derived = captured[0][0][3]
    assert derived["ioc"][0]["value"] == "path-traversal-like-input"
    assert "cve" not in derived


def test_ssh_telemetry_uses_configured_listener_port(monkeypatch):
    monkeypatch.setenv("AEGIS_SSH_PORT", "2222")
    observed = _base_observed("203.0.113.50", "session-1")
    assert observed["destination_port"] == 2222
    assert observed["service"] == "ssh"
    assert observed["protocol"] == "tcp"
    assert observed["network"]["schema_version"] == "1.0"
    assert observed["network"]["source"] == "sensor_socket"
    assert observed["network"]["transport"]["destination_port"] == 2222


class _FakeChannel:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


def test_ssh_command_reader_bounds_memory_and_discloses_truncation():
    raw = b"A" * 600
    channel = _FakeChannel([raw[:256], raw[256:512], raw[512:] + b"\n"])
    command, audit = _read_command(channel)

    assert command == "A" * 512
    entry = audit["truncated_fields"][0]
    assert entry["path"] == "observed.command"
    assert entry["original_length"] == 600
    assert entry["captured_length"] == 512
    assert entry["original_sha256"] == hashlib.sha256(raw).hexdigest()


def test_web_decoy_discloses_credential_truncation_without_losing_full_fingerprint(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    password = "p" * 5000
    response = client.post("/login", data={"username": "root", "password": password})

    assert response.status_code == 401
    observed = captured[0][0][1]
    assert len(observed["credential"]["password"]) == 4096
    capture = observed["sensor_capture"]
    entry = next(item for item in capture["truncated_fields"] if item["path"] == "observed.credential.password")
    assert entry["original_length"] == len(password)
    assert entry["captured_length"] == 4096
    assert entry["original_sha256"] == hashlib.sha256(password.encode()).hexdigest()


def test_legacy_reader_reports_oversized_input_rejection():
    line, status = _readline_with_status(io.BytesIO(b"A" * 600 + b"\n"))
    assert line == ""
    assert status["reason"] == "line_too_long"
    assert status["limit"] == 512
    assert status["bytes_observed_at_least"] == 513


def test_web_decoy_captures_unknown_paths_for_scan_detection(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    response = client.get("/wp-admin/probe-fixture")
    assert response.status_code == 404
    assert captured
    args, _kwargs = captured[-1]
    assert args[0] == "web.request"
    assert args[1]["path"] == "/wp-admin/probe-fixture"
    assert args[2] == "low"


def test_ssh_network_evidence_includes_peer_port_and_duration(monkeypatch):
    monkeypatch.setenv("AEGIS_SSH_PORT", "2222")
    observed = _base_observed("203.0.113.51", "session-2", 50123, duration_ms=1750)
    network = observed["network"]
    assert observed["source_port"] == 50123
    assert network["transport"]["source_port"] == 50123
    assert network["transport"]["destination_port"] == 2222
    assert network["connection"]["duration_ms"] == 1750


def test_web_decoy_captures_bounded_http_headers_as_network_evidence(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    response = client.get(
        "/",
        headers={
            "User-Agent": "fixture-agent/1.0",
            "Accept-Language": "it-IT,it;q=0.9",
            "X-Forwarded-For": "198.51.100.10",
            "Authorization": "Bearer must-not-be-captured",
        },
        environ_base={"REMOTE_PORT": "50124"},
    )
    assert response.status_code == 200
    observed = captured[-1][0][1]
    network = observed["network"]
    assert network["source"] == "http_request"
    assert network["capture_layer"] == "application"
    assert network["transport"]["source_port"] == 50124
    assert network["http"]["user_agent"] == "fixture-agent/1.0"
    assert network["http"]["headers"]["accept_language"] == "it-IT,it;q=0.9"
    assert network["http"]["headers"]["x_forwarded_for"] == "198.51.100.10"
    assert "authorization" not in network["http"]["headers"]
    assert observed["source_ip"] != "198.51.100.10"


def test_web_network_header_truncation_is_disclosed(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy.sensor, "emit", lambda *args, **kwargs: captured.append((args, kwargs)) or True)
    client = web_decoy.app.test_client()
    response = client.get("/", headers={"Accept-Language": "A" * 2000})
    assert response.status_code == 200
    observed = captured[-1][0][1]
    assert len(observed["network"]["http"]["headers"]["accept_language"]) == 1024
    entries = observed["sensor_capture"]["truncated_fields"]
    assert any(item["path"] == "observed.network.http.headers.accept_language" for item in entries)



def test_ftp_stor_uses_epsv_and_quarantines_without_local_execution(monkeypatch):
    payload = b"ftp-hostile-upload-fixture"
    captured = []
    monkeypatch.setattr(
        FTPHandler.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )
    monkeypatch.setattr(
        FTPHandler.sensor,
        "quarantine_artifact",
        lambda data, **kwargs: {
            "artifact_id": "artifact_ftp_fixture",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "original_name": "dropper.bin",
            "content_type": "application/octet-stream",
        },
    )

    data_server = BoundedThreadingTCPServer(("127.0.0.1", 0), FTPDataHandler, max_connections=2)
    control_server = BoundedThreadingTCPServer(("127.0.0.1", 0), FTPHandler, max_connections=2)
    FTPHandler.data_port = data_server.server_address[1]
    data_thread = threading.Thread(target=data_server.handle_request, daemon=True)
    control_thread = threading.Thread(target=control_server.handle_request, daemon=True)
    data_thread.start()
    control_thread.start()
    try:
        with socket.create_connection(control_server.server_address, timeout=2) as control:
            assert control.recv(1024).startswith(b"220 ")
            control.sendall(b"EPSV\r\n")
            epsv = control.recv(1024)
            assert str(FTPHandler.data_port).encode() in epsv

            with socket.create_connection(data_server.server_address, timeout=2) as data:
                control.sendall(b"STOR ../../dropper.bin\r\n")
                assert control.recv(1024).startswith(b"150 ")
                data.sendall(payload)
            assert control.recv(1024).startswith(b"226 ")
            control.sendall(b"QUIT\r\n")
            assert control.recv(1024).startswith(b"221 ")
        data_thread.join(timeout=2)
        control_thread.join(timeout=2)
    finally:
        data_server.server_close()
        control_server.server_close()

    event = next(args[1] for args, _kwargs in captured if args[0] == "artifact.quarantined")
    assert event["artifact"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert event["artifact"]["inline_serving"] is False
    assert payload.decode() not in str(event)
