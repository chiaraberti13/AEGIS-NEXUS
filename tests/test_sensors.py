import hashlib
import io
import socket
import threading

import paramiko

from aegis_nexus.network_evidence import MAX_SSH_ALGORITHMS
from aegis_nexus.sensors.legacy import FTPDataHandler, FTPHandler, _readline, _readline_with_status
from aegis_nexus.sensors.server import BoundedThreadingTCPServer
from aegis_nexus.sensors.ssh_decoy import (
    MAX_SSH_IDENTIFICATION,
    PERSONA as SSH_PERSONA,
    _base_observed,
    _fake_command,
    _identification_observed,
    _read_command,
)
from aegis_nexus.sensors import web_decoy


def _ssh_kexinit_bytes(kex, host_key, encryption, mac, compression) -> bytes:
    """Craft a raw SSH_MSG_KEXINIT payload as paramiko stores in remote_kex_init."""
    message = paramiko.Message()
    message.add_byte(bytes((20,)))  # SSH_MSG_KEXINIT
    message.add_bytes(b"\x00" * 16)  # cookie
    message.add_list(kex)
    message.add_list(host_key)
    message.add_list(encryption)  # client_to_server
    message.add_list(encryption)  # server_to_client
    message.add_list(mac)         # client_to_server
    message.add_list(mac)         # server_to_client
    message.add_list(compression)  # client_to_server
    message.add_list(compression)  # server_to_client
    message.add_boolean(False)    # first_kex_packet_follows
    message.add_int(0)            # reserved
    return message.asbytes()


class _FakeKexTransport:
    """Minimal stand-in exposing only the captured-KEXINIT attribute we read."""

    def __init__(self, raw: bytes | None) -> None:
        self._captured_remote_kex_init = raw


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


def test_ssh_client_version_is_observed_network_evidence_not_identity(monkeypatch):
    monkeypatch.setenv("AEGIS_SSH_PORT", "2222")
    observed = _identification_observed(
        "203.0.113.52", "session-3", "SSH-2.0-OpenSSH_8.9p1", 50125
    )
    network = observed["network"]
    # Captured directly by the sensor socket, at the application layer.
    assert network["source"] == "sensor_socket"
    assert network["capture_layer"] == "application"
    # The banner is recorded strictly under observed.network.ssh — a tooling
    # hint, never attacker identity and never an enrichment/derived claim.
    assert network["ssh"]["client_version"] == "SSH-2.0-OpenSSH_8.9p1"
    assert observed["source_port"] == 50125
    assert "enrichment" not in observed and "derived" not in observed


def test_ssh_client_version_is_bounded_and_discloses_truncation():
    hostile = "SSH-2.0-" + "A" * 1000
    observed = _identification_observed("203.0.113.53", "session-4", hostile)
    captured = observed["network"]["ssh"]["client_version"]
    # Bounded to RFC 4253's 255-byte identification-string limit.
    assert len(captured) == MAX_SSH_IDENTIFICATION
    # Evidence loss is disclosed, never silent, via the capture-metadata audit.
    assert observed["sensor_capture"]["truncated"] is True
    assert any(
        entry.get("path") == "observed.network.ssh.client_version"
        for entry in observed["sensor_capture"]["truncated_fields"]
    )


def test_ssh_client_version_survives_event_normalization():
    from aegis_nexus.model import normalize_event

    observed = _identification_observed(
        "203.0.113.54", "session-5", "SSH-2.0-libssh_0.10.6", 50126
    )
    event = normalize_event(
        {
            "honeypot": "ssh-decoy-01",
            "event_type": "connection.identified",
            "severity": "info",
            "observed": observed,
        }
    )
    assert event["observed"]["network"]["ssh"]["client_version"] == "SSH-2.0-libssh_0.10.6"


def test_ssh_hassh_and_offer_lists_are_observed_network_evidence():
    raw = _ssh_kexinit_bytes(
        ["curve25519-sha256"], ["ssh-ed25519"], ["aes128-ctr"],
        ["hmac-sha2-256"], ["none"],
    )
    observed = _identification_observed(
        "203.0.113.60", "s-hassh", "SSH-2.0-OpenSSH_9.6p1", 51000,
        transport_obj=_FakeKexTransport(raw),
    )
    ssh = observed["network"]["ssh"]
    # The client's offered KEXINIT lists are recorded verbatim (observed),
    # client-to-server direction for enc/mac/compression — a tooling hint.
    assert ssh["kex_algorithms"] == ["curve25519-sha256"]
    assert ssh["server_host_key_algorithms"] == ["ssh-ed25519"]
    assert ssh["encryption_algorithms"] == ["aes128-ctr"]
    assert ssh["mac_algorithms"] == ["hmac-sha2-256"]
    assert ssh["compression_algorithms"] == ["none"]
    # HASSH = md5(kex;enc_c2s;mac_c2s;comp_c2s) over the client offer lists.
    assert ssh["hassh_algorithms"] == "curve25519-sha256;aes128-ctr;hmac-sha2-256;none"
    assert ssh["hassh"] == "e97d07603350d1111ec2b64bf25413c9"
    assert (
        hashlib.md5(ssh["hassh_algorithms"].encode(), usedforsecurity=False).hexdigest()
        == ssh["hassh"]
    )
    # Still a tooling hint under observed.network — never identity/derived.
    assert ssh["client_version"] == "SSH-2.0-OpenSSH_9.6p1"
    assert "enrichment" not in observed and "derived" not in observed


def test_ssh_hassh_absent_when_no_kexinit_captured():
    # Fail-safe: if the KEXINIT could not be captured (e.g. a future paramiko
    # renames the internal hook), only the banner is recorded — no fabricated
    # fingerprint, and the decoy keeps working.
    observed = _identification_observed(
        "203.0.113.61", "s-nokex", "SSH-2.0-Go", 51001,
        transport_obj=_FakeKexTransport(None),
    )
    assert observed["network"]["ssh"] == {"client_version": "SSH-2.0-Go"}


def test_ssh_kexinit_offer_lists_are_bounded_and_skip_hassh_when_truncated():
    big_kex = [f"kex-{i}" for i in range(MAX_SSH_ALGORITHMS + 25)]
    raw = _ssh_kexinit_bytes(
        big_kex, ["ssh-ed25519"], ["aes128-ctr"], ["hmac-sha2-256"], ["none"],
    )
    observed = _identification_observed(
        "203.0.113.62", "s-big", "SSH-2.0-flooder", 51002,
        transport_obj=_FakeKexTransport(raw),
    )
    ssh = observed["network"]["ssh"]
    # Offer list is clamped to the shared cap...
    assert len(ssh["kex_algorithms"]) == MAX_SSH_ALGORITHMS
    # ...and a HASSH over truncated lists is NOT presented (it would match no
    # real client); the loss is disclosed, never silent.
    assert "hassh" not in ssh
    assert observed["sensor_capture"]["truncated"] is True
    assert any(
        entry.get("path") == "observed.network.ssh.algorithms"
        for entry in observed["sensor_capture"]["truncated_fields"]
    )


def test_ssh_hassh_survives_event_normalization():
    from aegis_nexus.model import normalize_event

    raw = _ssh_kexinit_bytes(
        ["curve25519-sha256"], ["ssh-ed25519"], ["aes128-ctr"],
        ["hmac-sha2-256"], ["none"],
    )
    observed = _identification_observed(
        "203.0.113.63", "s-norm", "SSH-2.0-OpenSSH_9.6p1", 51003,
        transport_obj=_FakeKexTransport(raw),
    )
    event = normalize_event({
        "honeypot": "ssh-decoy-01",
        "event_type": "connection.identified",
        "severity": "info",
        "observed": observed,
    })
    ssh = event["observed"]["network"]["ssh"]
    # The collector accepts and preserves the fingerprint (it stays within the
    # bounds validate_network_evidence independently enforces).
    assert ssh["hassh"] == "e97d07603350d1111ec2b64bf25413c9"
    assert ssh["kex_algorithms"] == ["curve25519-sha256"]


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
    assert event["artifact"]["transfer_correlation"]["strength"] == "heuristic"
    assert payload.decode() not in str(event)
