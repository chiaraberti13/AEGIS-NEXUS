from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

MAX_ARTIFACTS_PER_EVENT = 32
MAX_SCAN_CHARS = 4096

URL_RE = re.compile(r'''https?://[^\\s<>"'`]{1,2048}''', re.I)
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9_.-])"
)
IPV4_RE = re.compile(r"(?<![A-Za-z0-9_.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![A-Za-z0-9_.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
HASH_RE = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])"
)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _artifact(kind: str, value: str, evidence: str) -> dict[str, Any]:
    return {
        "type": kind,
        "value": value,
        "classification": "observed_artifact",
        "rationale": f"Exact artifact deterministically extracted from {evidence}.",
        "evidence": [evidence],
    }


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _normalize_domain(value: str) -> str | None:
    value = value.rstrip(".").lower()
    if len(value) > 253:
        return None
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(ascii_value):
        return None
    return ascii_value


def _extract_from_text(text: str, evidence: str) -> list[dict[str, Any]]:
    sample = text[:MAX_SCAN_CHARS]
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        if len(artifacts) >= MAX_ARTIFACTS_PER_EVENT:
            return
        key = (kind, value.casefold() if kind in {"domain", "url"} else value)
        if key in seen:
            return
        seen.add(key)
        artifacts.append(_artifact(kind, value, evidence))

    for match in URL_RE.finditer(sample):
        raw = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
        try:
            parsed = urlsplit(raw)
        except ValueError:
            continue
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        add("url", raw)
        host = parsed.hostname.rstrip(".")
        normalized_ip = _valid_ip(host)
        if normalized_ip:
            add("ip", normalized_ip)
        else:
            normalized_domain = _normalize_domain(host)
            if normalized_domain:
                add("domain", normalized_domain)

    for match in IPV4_RE.finditer(sample):
        normalized = _valid_ip(match.group(0))
        if normalized:
            add("ip", normalized)

    for match in IPV6_RE.finditer(sample):
        normalized = _valid_ip(match.group(0))
        if normalized:
            add("ip", normalized)

    for match in HASH_RE.finditer(sample):
        value = match.group(0).lower()
        add(_hash_type(value), value)

    for match in DOMAIN_RE.finditer(sample):
        normalized = _normalize_domain(match.group(0))
        if normalized:
            add("domain", normalized)

    return artifacts[:MAX_ARTIFACTS_PER_EVENT]


def derive_observed_artifacts(event: dict[str, Any]) -> dict[str, Any]:
    """Extract exact artifacts without assigning reputation or maliciousness."""
    observed = event.get("observed") or {}
    sources: list[tuple[str, str]] = []
    for field in ("command", "payload"):
        value = observed.get(field)
        if isinstance(value, str) and value:
            sources.append((value, f"observed.{field}"))

    if not sources:
        return event

    result = deepcopy(event)
    derived = result.setdefault("derived", {})
    existing = derived.get("ioc")
    iocs = list(existing) if isinstance(existing, list) else []

    seen: set[tuple[str, str]] = set()
    for item in iocs:
        if isinstance(item, dict) and item.get("type") and item.get("value") not in (None, ""):
            seen.add((str(item["type"]), str(item["value"]).casefold()))

    for text, evidence in sources:
        for artifact in _extract_from_text(text, evidence):
            key = (str(artifact["type"]), str(artifact["value"]).casefold())
            if key in seen:
                continue
            seen.add(key)
            iocs.append(artifact)
            if len(iocs) >= 128:
                break
        if len(iocs) >= 128:
            break

    if iocs:
        derived["ioc"] = iocs
    return result
