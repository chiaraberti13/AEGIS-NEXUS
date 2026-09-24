from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_PERSONA_BYTES = 65536
MAX_FAKE_FILES = 64
MAX_FAKE_FILE_BYTES = 4096


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


def load_persona() -> DecoyPersona:
    defaults = DecoyPersona()
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
