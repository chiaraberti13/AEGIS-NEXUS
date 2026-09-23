import hashlib
import io

from aegis_nexus.sensors.legacy import _readline, _readline_with_status
from aegis_nexus.sensors.ssh_decoy import _base_observed, _fake_command, _read_command
from aegis_nexus.sensors import web_decoy


def test_ssh_commands_are_emulated_not_executed():
    assert _fake_command("whoami") == "ops\n"
    assert "command not found" in _fake_command("curl http://example.invalid/payload")
    assert _fake_command("cat /etc/hostname") == "meridian-edge-01\n"


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
