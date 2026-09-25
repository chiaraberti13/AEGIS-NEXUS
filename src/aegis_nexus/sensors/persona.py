from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_PERSONA_BYTES = 65536
MAX_FAKE_FILES = 64
MAX_FAKE_FILE_BYTES = 4096
_PROCESS_PERSONA_SEED = os.urandom(32).hex()

_DEFAULT_PROFILES = (
    {
        "name": "meridian",
        "hostname_prefix": "edge",
        "username": "ops",
        "os_name": "Ubuntu",
        "os_version": "22.04.5 LTS",
        "ssh_version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "web_title": "Staff Portal",
        "web_heading": "Operations Staff Portal",
        "smtp_prefix": "mail",
        "ftp_banner": "FTP Service Ready",
        "telnet_banner": "Operations Gateway",
        "redis_version": "7.0.15",
        "mysql_version": "8.0.36",
    },
    {
        "name": "harbor",
        "hostname_prefix": "srv",
        "username": "svcops",
        "os_name": "Debian",
        "os_version": "12",
        "ssh_version": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "web_title": "Operations Console",
        "web_heading": "Internal Operations Console",
        "smtp_prefix": "mx",
        "ftp_banner": "FTP Server",
        "telnet_banner": "Service Console",
        "redis_version": "7.2.4",
        "mysql_version": "8.0.37",
    },
    {
        "name": "atlas",
        "hostname_prefix": "node",
        "username": "adminops",
        "os_name": "Ubuntu",
        "os_version": "24.04 LTS",
        "ssh_version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
        "web_title": "Service Portal",
        "web_heading": "Infrastructure Service Portal",
        "smtp_prefix": "smtp",
        "ftp_banner": "File Transfer Service",
        "telnet_banner": "Network Console",
        "redis_version": "7.2.5",
        "mysql_version": "8.4.0",
    },
)


@dataclass(frozen=True)
class DecoyPersona:
    name: str = "meridian"
    hostname: str = "meridian-edge-01"
    username: str = "ops"
    os_name: str = "Ubuntu"
    os_version: str = "22.04.5 LTS"
    ssh_version: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    web_title: str = "Meridian Portal"
    web_heading: str = "Meridian Logistics — Staff Portal"
    smtp_hostname: str = "meridian-mail"
    ftp_banner: str = "Meridian FTP Service"
    telnet_banner: str = "Meridian Gateway"
    redis_version: str = "7.2.0"
    mysql_version: str = "8.0.36"
    fake_files: dict[str, str] = field(default_factory=lambda: {
        "/etc/hostname": "meridian-edge-01\n",
        "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\n',
        "/home/ops/readme.txt": "Maintenance window: Sunday 02:00 UTC.\n",
    })

    def prompt(self) -> str:
        return f"{self.username}@{self.hostname}:~$ "


def _text(value: Any, default: str, limit: int) -> str:
    if not isinstance(value, str):
        return default
    clean = value.replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return clean[:limit] or default


def _fake_files(value: Any, default: dict[str, str]) -> dict[str, str]:
    if not isinstance(value, dict):
        return dict(default)
    result: dict[str, str] = {}
    for raw_path, raw_content in list(value.items())[:MAX_FAKE_FILES]:
        if not isinstance(raw_path, str) or not isinstance(raw_content, str):
            continue
        path = raw_path.strip()
        if not path.startswith("/") or ".." in Path(path).parts or len(path) > 256:
            continue
        encoded = raw_content.encode("utf-8", "replace")[:MAX_FAKE_FILE_BYTES]
        result[path] = encoded.decode("utf-8", "replace")
    return result or dict(default)


def _default_persona() -> DecoyPersona:
    seed = (
        os.getenv("AEGIS_DECOY_PERSONA_SEED", "").strip()
        or os.getenv("AEGIS_SENSOR_API_KEY", "").strip()
        or _PROCESS_PERSONA_SEED
    )
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()
    profile = _DEFAULT_PROFILES[int(digest[:8], 16) % len(_DEFAULT_PROFILES)]
    suffix = digest[8:14]
    hostname = f"{profile['hostname_prefix']}-{suffix}"
    smtp_hostname = f"{profile['smtp_prefix']}-{suffix}"
    username = str(profile["username"])
    os_name = str(profile["os_name"])
    os_version = str(profile["os_version"])
    return DecoyPersona(
        name=str(profile["name"]),
        hostname=hostname,
        username=username,
        os_name=os_name,
        os_version=os_version,
        ssh_version=str(profile["ssh_version"]),
        web_title=str(profile["web_title"]),
        web_heading=str(profile["web_heading"]),
        smtp_hostname=smtp_hostname,
        ftp_banner=str(profile["ftp_banner"]),
        telnet_banner=str(profile["telnet_banner"]),
        redis_version=str(profile["redis_version"]),
        mysql_version=str(profile["mysql_version"]),
        fake_files={
            "/etc/hostname": hostname + "\n",
            "/etc/os-release": f'NAME="{os_name}"\nVERSION="{os_version}"\n',
            f"/home/{username}/readme.txt": "Maintenance window: Sunday 02:00 UTC.\n",
        },
    )


def default_fingerprint_markers(persona: DecoyPersona) -> tuple[str, ...]:
    fields = (
        persona.hostname,
        persona.ssh_version,
        persona.web_title,
        persona.web_heading,
        persona.smtp_hostname,
        persona.ftp_banner,
        persona.telnet_banner,
        persona.redis_version,
        persona.mysql_version,
    )
    lowered = " ".join(fields).lower()
    return tuple(
        marker
        for marker in ("aegis", "honeypot", "cowrie", "kippo", "decoy")
        if marker in lowered
    )

def load_persona() -> DecoyPersona:
    defaults = _default_persona()
    raw = os.getenv("AEGIS_DECOY_PERSONA_JSON", "").strip()
    file_path = os.getenv("AEGIS_DECOY_PERSONA_FILE", "").strip()
    if file_path:
        try:
            data = Path(file_path).read_bytes()
        except OSError as exc:
            raise ValueError("unable to read AEGIS_DECOY_PERSONA_FILE") from exc
        if len(data) > MAX_PERSONA_BYTES:
            raise ValueError("decoy persona file exceeds size limit")
        raw = data.decode("utf-8", "strict")
    if not raw:
        return defaults
    if len(raw.encode("utf-8")) > MAX_PERSONA_BYTES:
        raise ValueError("decoy persona JSON exceeds size limit")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AEGIS_DECOY_PERSONA_JSON must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("decoy persona must be a JSON object")

    return DecoyPersona(
        name=_text(payload.get("name"), defaults.name, 64),
        hostname=_text(payload.get("hostname"), defaults.hostname, 63),
        username=_text(payload.get("username"), defaults.username, 64),
        os_name=_text(payload.get("os_name"), defaults.os_name, 64),
        os_version=_text(payload.get("os_version"), defaults.os_version, 96),
        ssh_version=_text(payload.get("ssh_version"), defaults.ssh_version, 128),
        web_title=_text(payload.get("web_title"), defaults.web_title, 128),
        web_heading=_text(payload.get("web_heading"), defaults.web_heading, 192),
        smtp_hostname=_text(payload.get("smtp_hostname"), defaults.smtp_hostname, 63),
        ftp_banner=_text(payload.get("ftp_banner"), defaults.ftp_banner, 128),
        telnet_banner=_text(payload.get("telnet_banner"), defaults.telnet_banner, 128),
        redis_version=_text(payload.get("redis_version"), defaults.redis_version, 32),
        mysql_version=_text(payload.get("mysql_version"), defaults.mysql_version, 32),
        fake_files=_fake_files(payload.get("fake_files"), defaults.fake_files),
    )
