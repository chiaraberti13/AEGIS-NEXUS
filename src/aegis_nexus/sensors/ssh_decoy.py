from __future__ import annotations

import hashlib
import os
import socketserver
import time
import uuid

import paramiko

from .base import SensorCapabilities, SensorConfig
from .capture import attach_capture_metadata, bounded_text, mark_truncation
from .client import SensorClient
from ..network_evidence import (
    MAX_SSH_ALGORITHM_LENGTH,
    MAX_SSH_ALGORITHMS,
    make_network_evidence,
)
from .server import BoundedThreadingTCPServer
from .persona import load_persona
from .registry import register_sensor

HOST_KEY = paramiko.RSAKey.generate(2048)
MAX_COMMAND = 512
# RFC 4253 §4.2 caps the SSH identification string at 255 bytes.
MAX_SSH_IDENTIFICATION = 255
# SSH_MSG_KEXINIT message type (RFC 4253 §12).
_SSH_MSG_KEXINIT = 20


class CapturingSSHTransport(paramiko.Transport):
    """paramiko Transport that snapshots the peer's raw KEXINIT for HASSH.

    paramiko stores the peer's raw ``SSH_MSG_KEXINIT`` bytes in
    ``remote_kex_init`` while parsing it, then clears the field once the key
    exchange completes — so it is unavailable after ``start_server`` returns.
    We override the (private) ``_parse_kex_init`` to call the real parser and
    then keep a copy. If a future paramiko renames that method, this override
    simply never runs and ``_captured_remote_kex_init`` stays unset: HASSH is
    then skipped (fail-safe), never wrong, and the decoy keeps working.
    """

    _captured_remote_kex_init: bytes | None = None

    def _parse_kex_init(self, m):  # type: ignore[override]
        super()._parse_kex_init(m)
        try:
            raw = self.remote_kex_init
            self._captured_remote_kex_init = bytes(raw) if raw else None
        except Exception:
            self._captured_remote_kex_init = None


def _bounded_algorithms(raw_list: list[str]) -> tuple[list[str], bool]:
    """Bound a KEXINIT name-list to the shared caps; report if it was truncated."""
    bounded: list[str] = []
    truncated = False
    for name in raw_list:
        if not name:  # paramiko yields [''] for an empty name-list
            continue
        if len(bounded) >= MAX_SSH_ALGORITHMS:
            truncated = True
            break
        if len(name) > MAX_SSH_ALGORITHM_LENGTH:
            name = name[:MAX_SSH_ALGORITHM_LENGTH]
            truncated = True
        bounded.append(name)
    return bounded, truncated


def _ssh_kex_fingerprint(transport: paramiko.Transport, audit: dict) -> dict | None:
    """Parse the captured client KEXINIT into bounded offer lists + a HASSH.

    Returns an ``observed.network.ssh`` fragment or ``None``. Everything is
    wrapped so a parsing surprise never propagates into the decoy's handler:
    the worst case is no fingerprint, never a crash. HASSH follows the
    Salesforce definition (``md5(kex;enc_c2s;mac_c2s;comp_c2s)``, client offer
    lists) and is a tooling hint, never identity. HASSH is only emitted when the
    offer lists fit within the caps untruncated, so a stored HASSH is always
    comparable with other tools' values.
    """
    try:
        raw = getattr(transport, "_captured_remote_kex_init", None)
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return None
        message = paramiko.Message(bytes(raw))
        if message.get_byte() != bytes((_SSH_MSG_KEXINIT,)):
            return None
        message.get_bytes(16)  # cookie
        lists = [message.get_list() for _ in range(8)]
        kex, host_key, enc_c2s, _enc_s2c, mac_c2s, _mac_s2c, comp_c2s, _comp_s2c = lists
        kex_b, t_kex = _bounded_algorithms(kex)
        host_key_b, t_host = _bounded_algorithms(host_key)
        enc_b, t_enc = _bounded_algorithms(enc_c2s)
        mac_b, t_mac = _bounded_algorithms(mac_c2s)
        comp_b, t_comp = _bounded_algorithms(comp_c2s)
        if not kex_b:
            return None  # not a sane KEXINIT — a real client always offers a KEX
        ssh_extra: dict = {
            "kex_algorithms": kex_b,
            "server_host_key_algorithms": host_key_b,
            "encryption_algorithms": enc_b,
            "mac_algorithms": mac_b,
            "compression_algorithms": comp_b,
        }
        if any((t_kex, t_host, t_enc, t_mac, t_comp)):
            # Offer lists exceeded the caps: store the bounded lists, disclose the
            # loss, and skip HASSH — a digest over truncated lists would not match
            # any real client and must not be presented as a fingerprint.
            original = sum(len(x) for x in (kex, host_key, enc_c2s, mac_c2s, comp_c2s))
            captured = sum(len(x) for x in (kex_b, host_key_b, enc_b, mac_b, comp_b))
            mark_truncation(
                audit,
                "observed.network.ssh.algorithms",
                original_length=original,
                captured_length=captured,
            )
        else:
            hassh_algorithms = ";".join(
                (",".join(kex_b), ",".join(enc_b), ",".join(mac_b), ",".join(comp_b))
            )
            ssh_extra["hassh"] = hashlib.md5(
                hassh_algorithms.encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            ssh_extra["hassh_algorithms"] = hassh_algorithms
        return ssh_extra
    except Exception:
        return None

def _base_observed(
    source_ip: str,
    sensor_session_id: str,
    source_port: int | None = None,
    *,
    duration_ms: int | None = None,
    destination_port: int | None = None,
) -> dict:
    destination_port = int(destination_port or os.getenv("AEGIS_SSH_PORT", "2222"))
    transport = {"protocol": "tcp", "destination_port": destination_port}
    observed = {
        "source_ip": source_ip,
        "service": "ssh",
        "protocol": "tcp",
        "destination_port": destination_port,
        "sensor_session_id": sensor_session_id,
    }
    if source_port is not None:
        observed["source_port"] = int(source_port)
        transport["source_port"] = int(source_port)
    connection = {"duration_ms": duration_ms} if duration_ms is not None else None
    observed["network"] = make_network_evidence(
        "sensor_socket",
        "application",
        transport=transport,
        connection=connection,
    )
    return observed


def _identification_observed(
    source_ip: str,
    sensor_session_id: str,
    client_version: str,
    source_port: int | None = None,
    *,
    destination_port: int | None = None,
    transport_obj: paramiko.Transport | None = None,
) -> dict:
    """Observed evidence for the attacker's SSH client identification + HASSH.

    The identification string and the KEXINIT offer lists are both
    attacker-controlled: they are bounded and recorded strictly as ``observed``
    tooling hints under ``observed.network.ssh`` (``client_version``, the
    offered ``*_algorithms`` lists, and the ``hassh`` digest) — never as
    attacker identity, and never a verdict. Evidence loss (truncation) is
    disclosed via the standard capture-metadata audit, like every other hostile
    sensor field.
    """
    audit: dict = {}
    bounded_version = bounded_text(
        client_version,
        MAX_SSH_IDENTIFICATION,
        "observed.network.ssh.client_version",
        audit,
    )
    destination_port = int(destination_port or os.getenv("AEGIS_SSH_PORT", "2222"))
    transport = {"protocol": "tcp", "destination_port": destination_port}
    observed: dict = {
        "source_ip": source_ip,
        "service": "ssh",
        "protocol": "tcp",
        "destination_port": destination_port,
        "sensor_session_id": sensor_session_id,
    }
    if source_port is not None:
        observed["source_port"] = int(source_port)
        transport["source_port"] = int(source_port)
    ssh_block: dict = {}
    if bounded_version:
        ssh_block["client_version"] = bounded_version
    if transport_obj is not None:
        kex_fingerprint = _ssh_kex_fingerprint(transport_obj, audit)
        if kex_fingerprint:
            ssh_block.update(kex_fingerprint)
    observed["network"] = make_network_evidence(
        "sensor_socket",
        "application",
        transport=transport,
        ssh=ssh_block or None,
    )
    attach_capture_metadata(observed, audit)
    return observed


PERSONA = load_persona()
FAKE_FILES = PERSONA.fake_files


class AegisSSHServer(paramiko.ServerInterface):
    def __init__(self, client: SensorClient, source_ip: str, source_port: int, destination_port: int, sensor_session_id: str):
        self.client = client
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.sensor_session_id = sensor_session_id
        self.username = ""

    def check_auth_password(self, username: str, password: str):
        audit: dict = {}
        self.username = bounded_text(
            username,
            128,
            "observed.credential.username",
            audit,
        )
        captured_password = bounded_text(
            password,
            4096,
            "observed.credential.password",
            audit,
            fingerprint_original=True,
        )
        observed = {
            **_base_observed(
                self.source_ip,
                self.sensor_session_id,
                self.source_port,
                destination_port=self.destination_port,
            ),
            "credential": {"username": self.username, "password": captured_password},
        }
        attach_capture_metadata(observed, audit)
        self.client.emit("credential", observed, "medium")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str):
        return "password"

    def check_channel_request(self, kind: str, chanid: int):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def _fake_command(command: str) -> str:
    clean = command.strip()
    if not clean:
        return ""
    if clean in {"exit", "logout"}:
        return "__EXIT__"
    if clean == "pwd":
        return f"/home/{PERSONA.username}\n"
    if clean in {"whoami", "id -un"}:
        return f"{PERSONA.username}\n"
    if clean == "id":
        return f"uid=1001({PERSONA.username}) gid=1001({PERSONA.username}) groups=1001({PERSONA.username}),27(sudo)\n"
    if clean in {"ls", "ls -la", "ls -l"}:
        return f"drwxr-xr-x 2 {PERSONA.username} {PERSONA.username} 4096 Sep 22 10:14 .\ndrwxr-xr-x 4 root root 4096 Sep 20 08:02 ..\n-rw-r--r-- 1 {PERSONA.username} {PERSONA.username} 48 Sep 21 17:44 readme.txt\n"
    if clean == "uname -a":
        return f"Linux {PERSONA.hostname} 5.15.0-119-generic #129-{PERSONA.os_name} SMP x86_64 GNU/Linux\n"
    if clean.startswith("cat "):
        path = clean[4:].strip()
        normalized = f"/home/{PERSONA.username}/readme.txt" if path in {"readme.txt", "./readme.txt"} else path
        return FAKE_FILES.get(normalized, f"cat: {path}: No such file or directory\n")
    return f"bash: {clean.split()[0][:64]}: command not found\n"


def _read_command(channel) -> tuple[str | None, dict]:
    """Read one hostile command with bounded memory and explicit truncation metadata."""
    prefix = bytearray()
    original_length = 0
    digest = hashlib.sha256()
    truncated = False

    while True:
        chunk = channel.recv(256)
        if not chunk:
            return None, {}
        for value in chunk:
            if value in (10, 13):
                audit: dict = {}
                if truncated:
                    mark_truncation(
                        audit,
                        "observed.command",
                        original_length=original_length,
                        captured_length=len(prefix),
                        original_sha256=digest.hexdigest(),
                    )
                command = bytes(prefix).decode("utf-8", "replace").strip()
                return command, audit
            original_length += 1
            digest.update(bytes((value,)))
            if len(prefix) < MAX_COMMAND:
                prefix.append(value)
            else:
                truncated = True


class SSHHandler(socketserver.BaseRequestHandler):
    sensor = SensorClient("ssh-decoy-01")

    def handle(self):
        source_ip = str(self.client_address[0])
        source_port = int(self.client_address[1])
        sensor_session_id = uuid.uuid4().hex
        destination_port = int(self.server.server_address[1])
        connection_started = time.monotonic()
        self.request.settimeout(20)
        self.sensor.emit(
            "connection",
            _base_observed(source_ip, sensor_session_id, source_port, destination_port=destination_port),
        )
        transport = CapturingSSHTransport(self.request)
        transport.local_version = PERSONA.ssh_version
        transport.add_server_key(HOST_KEY)
        server = AegisSSHServer(self.sensor, source_ip, source_port, destination_port, sensor_session_id)
        try:
            transport.start_server(server=server)
            client_version = getattr(transport, "remote_version", "") or ""
            has_kex = bool(getattr(transport, "_captured_remote_kex_init", None))
            if client_version or has_kex:
                self.sensor.emit(
                    "connection.identified",
                    _identification_observed(
                        source_ip,
                        sensor_session_id,
                        client_version,
                        source_port,
                        destination_port=destination_port,
                        transport_obj=transport,
                    ),
                )
            channel = transport.accept(10)
            if channel is None:
                return
            channel.settimeout(30)
            channel.send(f"{PERSONA.os_name} {PERSONA.os_version}\\r\n\\r\n{PERSONA.prompt()}")
            while transport.is_active():
                command, audit = _read_command(channel)
                if command is None:
                    break
                if not command:
                    channel.send(PERSONA.prompt())
                    continue
                observed = {
                    **_base_observed(source_ip, sensor_session_id, source_port, destination_port=destination_port),
                    "command": command,
                }
                attach_capture_metadata(observed, audit)
                self.sensor.emit("command", observed, "medium")
                response = _fake_command(command)
                if response == "__EXIT__":
                    channel.send("logout\r\n")
                    break
                channel.send(response.replace("\n", "\r\n") + PERSONA.prompt())
        except (paramiko.SSHException, EOFError, OSError):
            return
        finally:
            duration_ms = max(0, int(round((time.monotonic() - connection_started) * 1000)))
            self.sensor.emit(
                "connection.closed",
                _base_observed(
                    source_ip,
                    sensor_session_id,
                    source_port,
                    duration_ms=duration_ms,
                    destination_port=destination_port,
                ),
            )
            transport.close()


@register_sensor
class SSHSensorPlugin:
    name = "ssh"
    capabilities = SensorCapabilities(
        protocols=("ssh", "tcp"),
        event_types=("connection", "connection.identified", "connection.closed", "credential", "command"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection", "ssh"),
        captures_credentials=True,
        captures_commands=True,
        executes_attacker_input=False,
    )

    @classmethod
    def config_from_env(cls) -> SensorConfig:
        return SensorConfig(
            sensor_id=os.getenv("AEGIS_HONEYPOT_ID", "ssh-decoy-01")[:96],
            enabled=os.getenv("AEGIS_SSH_ENABLED", "true").lower() in {"1", "true", "yes"},
            bind_host=os.getenv("AEGIS_SSH_BIND", "0.0.0.0"),
            ports={"ssh": int(os.getenv("AEGIS_SSH_PORT", "2222"))},
            options={
                "max_connections": max(1, min(int(os.getenv("AEGIS_SENSOR_MAX_CONNECTIONS", "32")), 256)),
            },
        )

    @classmethod
    def run(cls, config: SensorConfig) -> None:
        if not config.enabled:
            return
        port = config.port("ssh")
        SSHHandler.sensor = SensorClient(config.sensor_id)
        heartbeat = SSHHandler.sensor.start_heartbeat()
        try:
            with BoundedThreadingTCPServer(
                (config.bind_host, port),
                SSHHandler,
                max_connections=int(config.options.get("max_connections", 32)),
            ) as server:
                server.serve_forever()
        finally:
            heartbeat.stop()


def main():
    SSHSensorPlugin.run(SSHSensorPlugin.config_from_env())


if __name__ == "__main__":
    main()
