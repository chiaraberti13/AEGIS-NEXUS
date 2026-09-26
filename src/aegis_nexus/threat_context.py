from __future__ import annotations

import ipaddress
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .cti_stix import StixExportError, import_stix_bundle
from .custom_feed import CustomFeedAdapter, CustomFeedAdapterError
from .threat_intelligence import ThreatIntelligenceProvider

SUPPORTED_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ThreatContextError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_text(value: Any, limit: int) -> str | None:
    if value in (None, ""):
        return None
    return CONTROL_RE.sub("", str(value)).strip()[:limit]


def _normalize_domain(value: Any) -> str | None:
    text = _clean_text(value, 253)
    if not text:
        return None
    text = text.rstrip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return text if DOMAIN_RE.fullmatch(text) else None


def _normalize_url(value: Any) -> str | None:
    text = _clean_text(value, 2048)
    if not text:
        return None
    try:
        parsed = urlsplit(text)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    host = parsed.hostname.rstrip(".")
    normalized_ip = None
    try:
        normalized_ip = str(ipaddress.ip_address(host))
    except ValueError:
        host = _normalize_domain(host)
        if not host:
            return None
    if normalized_ip:
        host = f"[{normalized_ip}]" if ":" in normalized_ip else normalized_ip
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query or "", parsed.fragment or ""))


def normalize_indicator(kind: Any, value: Any) -> tuple[str, str] | None:
    kind_text = _clean_text(kind, 16)
    if not kind_text:
        return None
    kind_text = kind_text.lower()
    if kind_text not in SUPPORTED_TYPES:
        return None
    if kind_text == "ip":
        try:
            return kind_text, str(ipaddress.ip_address(str(value)))
        except ValueError:
            return None
    if kind_text == "domain":
        normalized = _normalize_domain(value)
        return (kind_text, normalized) if normalized else None
    if kind_text == "url":
        normalized = _normalize_url(value)
        return (kind_text, normalized) if normalized else None
    text = _clean_text(value, 128)
    if not text:
        return None
    text = text.lower()
    if len(text) != HASH_LENGTHS[kind_text] or not HEX_RE.fullmatch(text):
        return None
    return kind_text, text


def _iso_timestamp(value: Any) -> str | None:
    text = _clean_text(value, 128)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _indicator_aging(
    item: dict[str, Any],
    *,
    now_iso: str,
    feed_generated_at: str | None,
    stale_after_days: int,
    aged_after_days: int,
) -> dict[str, Any] | None:
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    candidates = (
        ("last_seen", _iso_timestamp(item.get("last_seen"))),
        ("first_seen", _iso_timestamp(item.get("first_seen"))),
        ("feed_generated_at", _iso_timestamp(feed_generated_at)),
    )
    basis = next(((name, value) for name, value in candidates if value), None)
    if basis is None:
        return None
    basis_name, basis_value = basis
    reference = datetime.fromisoformat(basis_value)
    age_days = max(0, int((now - reference).total_seconds() // 86400))
    stale = max(1, int(stale_after_days))
    aged = max(stale + 1, int(aged_after_days))
    if age_days < stale:
        state = "fresh"
        score = 100
    elif age_days >= aged:
        state = "aged"
        score = 0
    else:
        state = "stale"
        score = max(0, round(100 * (aged - age_days) / (aged - stale)))

    result: dict[str, Any] = {
        "basis": basis_name,
        "reference_time": basis_value,
        "age_days": age_days,
        "state": state,
        "freshness_score": score,
    }
    valid_from = _iso_timestamp(item.get("valid_from"))
    valid_until = _iso_timestamp(item.get("valid_until"))
    if valid_from and now < datetime.fromisoformat(valid_from):
        result["validity_state"] = "not_yet_valid"
    elif valid_until and now > datetime.fromisoformat(valid_until):
        result["validity_state"] = "expired"
    elif valid_from or valid_until:
        result["validity_state"] = "active"
    else:
        result["validity_state"] = "unspecified"
    return result


def _bounded_metadata(item: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    labels = item.get("labels")
    if isinstance(labels, list):
        clean_labels = []
        for label in labels[:16]:
            text = _clean_text(label, 128)
            if text:
                clean_labels.append(text)
        if clean_labels:
            result["labels"] = clean_labels
    confidence = item.get("confidence")
    if confidence is not None:
        try:
            numeric = int(confidence)
        except (TypeError, ValueError):
            numeric = None
        if numeric is not None and 0 <= numeric <= 100:
            result["confidence"] = numeric
    for key, limit in (("description", 512), ("reference", 1024), ("first_seen", 128), ("last_seen", 128)):
        text = _clean_text(item.get(key), limit)
        if text:
            result[key] = text
    valid_from = _iso_timestamp(item.get("valid_from"))
    valid_until = _iso_timestamp(item.get("valid_until"))
    if valid_from and valid_until:
        if datetime.fromisoformat(valid_from) <= datetime.fromisoformat(valid_until):
            result["valid_from"] = valid_from
            result["valid_until"] = valid_until
    elif valid_from:
        result["valid_from"] = valid_from
    elif valid_until:
        result["valid_until"] = valid_until
    return result


class LocalThreatContextEnricher(ThreatIntelligenceProvider):
    """Offline exact-match threat context from an operator-supplied JSON feed."""

    provider_id = "local-json"
    network_requests = False

    def __init__(
        self,
        feed_path: str | None = None,
        *,
        max_bytes: int = 20 * 1024 * 1024,
        max_indicators: int = 100_000,
        max_matches: int = 32,
        adapter_config: dict[str, Any] | None = None,
        stale_after_days: int = 30,
        aged_after_days: int = 90,
    ):
        self.path = Path(feed_path).expanduser() if feed_path else None
        self.max_bytes = max(1024, min(int(max_bytes), 100 * 1024 * 1024))
        self.max_indicators = max(1, min(int(max_indicators), 500_000))
        self.max_matches = max(1, min(int(max_matches), 128))
        self.adapter = CustomFeedAdapter(adapter_config) if adapter_config is not None else None
        self.stale_after_days = max(1, min(int(stale_after_days), 3650))
        self.aged_after_days = max(self.stale_after_days + 1, min(int(aged_after_days), 7300))
        self.source: str | None = None
        self.generated_at: str | None = None
        self.loaded_at: str | None = None
        self.error: str | None = None
        self._index: dict[tuple[str, str], list[dict[str, Any]]] = {}
        if self.path:
            self._load()

    def _load(self) -> None:
        try:
            with self.path.open("rb") as handle:
                raw_bytes = handle.read(self.max_bytes + 1)
            if len(raw_bytes) > self.max_bytes:
                raise ThreatContextError("feed_too_large")
            raw = raw_bytes.decode("utf-8")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ThreatContextError("feed_root_must_be_object")
            if payload.get("type") == "bundle":
                if self.adapter is not None:
                    raise ThreatContextError("custom_adapter_not_supported_for_stix_bundle")
                try:
                    indicators = import_stix_bundle(payload, max_objects=self.max_indicators)
                except StixExportError as exc:
                    raise ThreatContextError(str(exc)) from exc
                self.provider_id = "local-stix"
                bundle_id = _clean_text(payload.get("id"), 128)
                self.source = f"stix-bundle:{bundle_id or self.path.name}"
                self.generated_at = None
            else:
                if self.adapter is not None:
                    try:
                        payload = self.adapter.adapt(payload, max_indicators=self.max_indicators)
                    except CustomFeedAdapterError as exc:
                        raise ThreatContextError(str(exc)) from exc
                    self.provider_id = "local-custom-json"
                else:
                    self.provider_id = "local-json"
                indicators = payload.get("indicators")
                if not isinstance(indicators, list):
                    raise ThreatContextError("indicators_must_be_list")
                if len(indicators) > self.max_indicators:
                    raise ThreatContextError("too_many_indicators")
                source = _clean_text(payload.get("source"), 256)
                self.source = source or f"local-threat-feed:{self.path.name}"
                self.generated_at = _clean_text(payload.get("generated_at"), 128)
            index: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for raw_item in indicators:
                if not isinstance(raw_item, dict):
                    continue
                normalized = normalize_indicator(raw_item.get("type"), raw_item.get("value"))
                if not normalized:
                    continue
                kind, value = normalized
                entry = {"type": kind, "value": value, **_bounded_metadata(raw_item)}
                bucket = index.setdefault((kind, value), [])
                if len(bucket) < 8 and entry not in bucket:
                    bucket.append(entry)
            self._index = index
            self.loaded_at = _now()
            self.error = None
        except Exception as exc:
            self._index = {}
            self.loaded_at = None
            self.error = str(exc)[:160] if isinstance(exc, ThreatContextError) else type(exc).__name__

    def indicators(self) -> list[dict[str, Any]]:
        """Return bounded normalized feed indicators for explicit CTI export."""
        items: list[dict[str, Any]] = []
        for key in sorted(self._index):
            for item in self._index[key]:
                items.append(deepcopy(item))
                if len(items) >= self.max_indicators:
                    return items
        return items

    def status(self) -> dict[str, Any]:
        return {
            "provider": self.provider_id,
            "mode": "local_offline_exact_match",
            "network_requests": self.network_requests,
            "configured": self.path is not None,
            "ready": self.path is not None and self.error is None and self.loaded_at is not None,
            "feed": self.path.name if self.path else None,
            "custom_adapter": self.adapter is not None,
            "aging_policy": {"stale_after_days": self.stale_after_days, "aged_after_days": self.aged_after_days},
            "source": self.source,
            "generated_at": self.generated_at,
            "loaded_at": self.loaded_at,
            "indicator_keys": len(self._index),
            "error": self.error,
        }

    def _candidates(self, event: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
        candidates: list[tuple[str, str, list[str]]] = []
        observed = event.get("observed") or {}
        source_ip = observed.get("source_ip")
        normalized_source = normalize_indicator("ip", source_ip) if source_ip else None
        if normalized_source:
            candidates.append((normalized_source[0], normalized_source[1], ["observed.source_ip"]))
        derived = event.get("derived") or {}
        for item in (derived.get("ioc") or [])[:128]:
            if not isinstance(item, dict):
                continue
            normalized = normalize_indicator(item.get("type"), item.get("value"))
            if not normalized:
                continue
            evidence = item.get("evidence")
            paths = [str(value)[:256] for value in evidence[:16]] if isinstance(evidence, list) else ["derived.ioc"]
            candidates.append((normalized[0], normalized[1], paths or ["derived.ioc"]))
        return candidates

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self._index:
            return event
        enrichment = event.get("enrichment") or {}
        if "threat_context" in enrichment:
            return event
        matches: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for kind, value, evidence in self._candidates(event):
            for feed_item in self._index.get((kind, value), []):
                fingerprint = (kind, value, json.dumps(feed_item, ensure_ascii=False, sort_keys=True))
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                match = {**feed_item, "evidence": evidence}
                aging = _indicator_aging(
                    feed_item,
                    now_iso=_now(),
                    feed_generated_at=self.generated_at,
                    stale_after_days=self.stale_after_days,
                    aged_after_days=self.aged_after_days,
                )
                if aging is not None:
                    match["aging"] = aging
                matches.append(match)
                if len(matches) >= self.max_matches:
                    break
            if len(matches) >= self.max_matches:
                break
        if not matches:
            return event
        result = deepcopy(event)
        enriched_at = _now()
        result.setdefault("enrichment", {})["threat_context"] = {
            "provider": self.provider_id,
            "source": self.source or (f"local-threat-feed:{self.path.name}" if self.path else "local-threat-feed"),
            "retrieved_at": self.loaded_at or enriched_at,
            "observed_at": enriched_at,
            "data": {
                "match_policy": "exact",
                "feed_generated_at": self.generated_at,
                "matches": matches,
            },
        }
        return result
