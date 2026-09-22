from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_EXTERNAL_RESPONSE_BYTES = 131_072
MAX_ENRICHMENT_STRING = 4096
MAX_ENRICHMENT_ITEMS = 128
MAX_ENRICHMENT_DEPTH = 6


class EnrichmentValidationError(ValueError):
    pass


class EnrichmentProviderError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise EnrichmentValidationError("invalid IP address") from exc


def require_global_ip(value: str) -> str:
    normalized = normalize_ip(value)
    if not ipaddress.ip_address(normalized).is_global:
        raise EnrichmentValidationError("external provider lookup requires a global IP address")
    return normalized


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > MAX_ENRICHMENT_DEPTH:
        raise EnrichmentValidationError("enrichment nesting too deep")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_ENRICHMENT_STRING]
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:MAX_ENRICHMENT_ITEMS]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, raw_value in list(value.items())[:MAX_ENRICHMENT_ITEMS]:
            key = str(raw_key)[:96]
            if not key:
                continue
            result[key] = _bounded(raw_value, depth + 1)
        return result
    return str(value)[:MAX_ENRICHMENT_STRING]


def _iso_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EnrichmentValidationError("observed_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnrichmentValidationError("invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def normalize_manual_enrichment(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EnrichmentValidationError("enrichment must be an object")
    kind = str(payload.get("kind") or "").strip()[:64]
    source = str(payload.get("source") or "").strip()[:160]
    source_reference = str(payload.get("source_reference") or "").strip()[:256]
    if not kind or not source:
        raise EnrichmentValidationError("kind and source are required")
    if any(ord(char) < 32 for char in kind + source + source_reference):
        raise EnrichmentValidationError("enrichment metadata contains control characters")
    data = _bounded(payload.get("data") if "data" in payload else {})
    if not isinstance(data, dict):
        raise EnrichmentValidationError("data must be an object")
    return {
        "kind": kind,
        "source": source,
        "source_reference": source_reference,
        "observed_at": _iso_timestamp(payload.get("observed_at")),
        "data": data,
        "provenance": "external_enrichment",
    }


def _selected_abuseipdb_data(data: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "ipAddress",
        "isPublic",
        "ipVersion",
        "isWhitelisted",
        "abuseConfidenceScore",
        "countryCode",
        "usageType",
        "isp",
        "domain",
        "hostnames",
        "isTor",
        "totalReports",
        "numDistinctUsers",
        "lastReportedAt",
    )
    return _bounded({key: data.get(key) for key in allowed if key in data})


def fetch_abuseipdb(
    ip: str,
    api_key: str,
    *,
    max_age_days: int = 90,
    timeout: float = 5.0,
) -> dict[str, Any]:
    normalized_ip = require_global_ip(ip)
    if not api_key:
        raise EnrichmentProviderError("AbuseIPDB API key is not configured")
    max_age_days = max(1, min(int(max_age_days), 365))
    timeout = max(1.0, min(float(timeout), 20.0))
    query = urllib.parse.urlencode({
        "ipAddress": normalized_ip,
        "maxAgeInDays": max_age_days,
    })
    request = urllib.request.Request(
        f"{ABUSEIPDB_CHECK_URL}?{query}",
        headers={
            "Accept": "application/json",
            "Key": api_key,
            "User-Agent": "AEGIS-NEXUS/0.2",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_EXTERNAL_RESPONSE_BYTES + 1)
            if len(body) > MAX_EXTERNAL_RESPONSE_BYTES:
                raise EnrichmentProviderError("provider response too large")
            status = int(getattr(response, "status", 200))
            if status < 200 or status >= 300:
                raise EnrichmentProviderError(f"provider returned HTTP {status}")
    except urllib.error.HTTPError as exc:
        raise EnrichmentProviderError(f"provider returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EnrichmentProviderError("provider request failed") from exc

    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrichmentProviderError("provider returned invalid JSON") from exc
    raw_data = decoded.get("data") if isinstance(decoded, dict) else None
    if not isinstance(raw_data, dict):
        raise EnrichmentProviderError("provider response is missing data")

    return {
        "kind": "reputation",
        "source": "AbuseIPDB API v2",
        "source_reference": "check",
        "observed_at": utc_now(),
        "data": _selected_abuseipdb_data(raw_data),
        "provenance": "external_enrichment",
    }
