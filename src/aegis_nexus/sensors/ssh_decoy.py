from __future__ import annotations

import os
import socketserver
import time

import paramiko

from .client import SensorClient

HOST_KEY = paramiko.RSAKey.generate(2048)
MAX_COMMAND = 512

FAKE_FILES = {
    "/etc/hostname": "meridian-edge-01\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\n',
    "/home/ops/readme.txt": "Maintenance window: Sunday 02:00 UTC.\n",
}


class AegisSSHServer(paramiko.ServerInterface):
    def __init__(self, client: SensorClient, source_ip: str):
        self.client = client
        self.source_ip = source_ip
        self.username = ""

    def check_auth_password(self, username: str, password: str):
        self.username = username[:128]
        self.client.emit(
            "credential",
            {
                "source_ip": self.source_ip,
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "credential": {"username": self.username, "password": password[:256]},
            },
            "medium",
        )
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


class SSHHandler(socketserver.BaseRequestHandler):
    sensor = SensorClient("ssh-decoy-01")

    def handle(self):
        source_ip = str(self.client_address[0])
        self.request.settimeout(20)
        self.sensor.emit("connection", {"source_ip": source_ip, "service": "ssh", "protocol": "tcp", "destination_port": 22})
        transport = paramiko.Transport(self.request)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        transport.add_server_key(HOST_KEY)
        server = AegisSSHServer(self.sensor, source_ip)
        try:
            transport.start_server(server=server)
            channel = transport.accept(10)
            if channel is None:
                return
            channel.settimeout(30)
            channel.send("Ubuntu 22.04.5 LTS\r\n\r\nops@meridian-edge-01:~$ ")
            buffer = b""
            while transport.is_active():
                chunk = channel.recv(256)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > MAX_COMMAND:
                    buffer = buffer[:MAX_COMMAND]
                if b"\n" not in buffer and b"\r" not in buffer:
                    continue
                raw = buffer.replace(b"\r", b"\n").split(b"\n", 1)[0]
                buffer = b""
                command = raw.decode("utf-8", "replace").strip()[:MAX_COMMAND]
                if not command:
                    channel.send("ops@meridian-edge-01:~$ ")
                    continue
                self.sensor.emit(
                    "command",
                    {"source_ip": source_ip, "service": "ssh", "protocol": "tcp", "destination_port": 22, "command": command},
                    "medium",
                )
                response = _fake_command(command)
                if response == "__EXIT__":
                    channel.send("logout\r\n")
                    break
                channel.send(response.replace("\n", "\r\n") + "ops@meridian-edge-01:~$ ")
        except (paramiko.SSHException, EOFError, OSError):
            return
        finally:
            transport.close()


class ThreadingSSHServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.getenv("AEGIS_SSH_PORT", "2222"))
    SSHHandler.sensor = SensorClient(os.getenv("AEGIS_HONEYPOT_ID", "ssh-decoy-01"))
    with ThreadingSSHServer(("0.0.0.0", port), SSHHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
