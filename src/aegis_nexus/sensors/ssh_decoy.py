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
from ..network_evidence import make_network_evidence
from .server import BoundedThreadingTCPServer
from .registry import register_sensor

HOST_KEY = paramiko.RSAKey.generate(2048)
MAX_COMMAND = 512

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


FAKE_FILES = {
    "/etc/hostname": "meridian-edge-01\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\n',
    "/home/ops/readme.txt": "Maintenance window: Sunday 02:00 UTC.\n",
}


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
        return "/home/ops\n"
    if clean in {"whoami", "id -un"}:
        return "ops\n"
    if clean == "id":
        return "uid=1001(ops) gid=1001(ops) groups=1001(ops),27(sudo)\n"
    if clean in {"ls", "ls -la", "ls -l"}:
        return "drwxr-xr-x 2 ops ops 4096 Sep 22 10:14 .\ndrwxr-xr-x 4 root root 4096 Sep 20 08:02 ..\n-rw-r--r-- 1 ops ops 48 Sep 21 17:44 readme.txt\n"
    if clean == "uname -a":
        return "Linux meridian-edge-01 5.15.0-119-generic #129-Ubuntu SMP x86_64 GNU/Linux\n"
    if clean.startswith("cat "):
        path = clean[4:].strip()
        normalized = "/home/ops/readme.txt" if path in {"readme.txt", "./readme.txt"} else path
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
        transport = paramiko.Transport(self.request)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        transport.add_server_key(HOST_KEY)
        server = AegisSSHServer(self.sensor, source_ip, source_port, destination_port, sensor_session_id)
        try:
            transport.start_server(server=server)
            channel = transport.accept(10)
            if channel is None:
                return
            channel.settimeout(30)
            channel.send("Ubuntu 22.04.5 LTS\r\n\r\nops@meridian-edge-01:~$ ")
            while transport.is_active():
                command, audit = _read_command(channel)
                if command is None:
                    break
                if not command:
                    channel.send("ops@meridian-edge-01:~$ ")
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
                channel.send(response.replace("\n", "\r\n") + "ops@meridian-edge-01:~$ ")
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
        event_types=("connection", "connection.closed", "credential", "command"),
        interaction_mode="emulated",
        network_evidence=("transport", "connection"),
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
