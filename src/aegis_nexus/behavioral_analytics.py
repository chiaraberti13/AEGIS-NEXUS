from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

ANALYTICS_SCHEMA_VERSION = "1.0"
BASELINE_WINDOWS = (("24h", timedelta(hours=24)), ("7d", timedelta(days=7)), ("30d", timedelta(days=30)))
DEFAULT_MIN_SAMPLES = 20


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _observed(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("observed")
    return value if isinstance(value, dict) else {}


def _derived(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("derived")
    return value if isinstance(value, dict) else {}


def _username(event: dict[str, Any]) -> str | None:
    credential = _observed(event).get("credential")
    if not isinstance(credential, dict):
        return None
    value = str(credential.get("username") or "").strip()
    return value[:160] or None


def _command(event: dict[str, Any]) -> str | None:
    value = _observed(event).get("command")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:4096] or None


def _payload_sha256(event: dict[str, Any]) -> str | None:
    payload = _observed(event).get("payload")
    if not isinstance(payload, str) or not payload:
        return None
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def _ioc_values(event: dict[str, Any], kinds: set[str]) -> set[str]:
    values: set[str] = set()
    for item in _derived(event).get("ioc", []) or []:
        if not isinstance(item, dict) or str(item.get("type") or "").lower() not in kinds:
            continue
        value = str(item.get("value") or "").strip()
        if value:
            values.add(value.casefold())
    return values


def _dimensions(event: dict[str, Any]) -> dict[str, set[str]]:
    source_ip = str(event.get("source_ip") or _observed(event).get("source_ip") or "").strip()
    enrichment = event.get("enrichment") if isinstance(event.get("enrichment"), dict) else {}
    geo = enrichment.get("geo") if isinstance(enrichment.get("geo"), dict) else {}
    geo_data = geo.get("data") if isinstance(geo.get("data"), dict) else {}
    asn_block = enrichment.get("asn") if isinstance(enrichment.get("asn"), dict) else {}
    asn_data = asn_block.get("data") if isinstance(asn_block.get("data"), dict) else {}
    country = str(event.get("country") or geo_data.get("country") or "").strip()
    asn = str(event.get("asn") or asn_data.get("asn") or "").strip()
    username = _username(event)
    payload_hash = _payload_sha256(event)
    return {
        "source_ip": {source_ip} if source_ip else set(),
        "country": {country} if country else set(),
        "asn": {asn} if asn else set(),
        "username": {username} if username else set(),
        "payload_sha256": {payload_hash} if payload_hash else set(),
        "url_domain": _ioc_values(event, {"url", "domain"}),
    }


@dataclass(frozen=True)
class BaselinePolicy:
    min_samples: int = DEFAULT_MIN_SAMPLES

    def __post_init__(self) -> None:
        if not 1 <= int(self.min_samples) <= 100_000:
            raise ValueError("invalid_min_samples")


class BehavioralAnalytics:
    def __init__(self, *, min_samples: int = DEFAULT_MIN_SAMPLES):
        self.policy = BaselinePolicy(min_samples=int(min_samples))

    def baseline(self, event: dict[str, Any], history: list[dict[str, Any]], *, truncated: bool = False) -> dict[str, Any]:
        anchor = _timestamp(event.get("timestamp"))
        if anchor is None:
            raise ValueError("invalid_analytics_anchor_timestamp")
        windows: dict[str, Any] = {}
        for label, duration in BASELINE_WINDOWS:
            start = anchor - duration
            selected = [
                item for item in history
                if (ts := _timestamp(item.get("timestamp"))) is not None and start <= ts <= anchor
            ]
            values = {key: set() for key in _dimensions(event)}
            for item in selected:
                for key, entries in _dimensions(item).items():
                    values[key].update(entries)
            windows[label] = {
                "start": start.isoformat(),
                "end": anchor.isoformat(),
                "sample_count": len(selected),
                "ready": len(selected) >= self.policy.min_samples and not truncated,
                "minimum_samples": self.policy.min_samples,
                "distinct": {key: len(entries) for key, entries in values.items()},
                "values": {key: sorted(entries)[:256] for key, entries in values.items()},
                "values_truncated": {key: len(entries) > 256 for key, entries in values.items()},
            }
        return {
            "schema_version": ANALYTICS_SCHEMA_VERSION,
            "anchor_event_id": str(event.get("id") or "")[:128],
            "anchor_timestamp": anchor.isoformat(),
            "baseline_windows": windows,
            "history_truncated": bool(truncated),
            "policy": {
                "minimum_samples": self.policy.min_samples,
                "cold_start_suppresses_findings": True,
                "truncated_history_suppresses_findings": True,
            },
        }

    def evaluate(self, event: dict[str, Any], history: list[dict[str, Any]], *, truncated: bool = False) -> dict[str, Any]:
        baseline = self.baseline(event, history, truncated=truncated)
        findings: list[dict[str, Any]] = []
        long_window = baseline["baseline_windows"]["30d"]
        if not long_window["ready"]:
            return {**baseline, "findings": findings}

        current = _dimensions(event)
        labels = {
            "source_ip": "New source IP",
            "country": "New country",
            "asn": "New ASN",
            "username": "New username",
            "payload_sha256": "New payload hash",
            "url_domain": "New URL/domain",
        }
        anchor = _timestamp(event.get("timestamp"))
        assert anchor is not None
        start_30d = anchor - timedelta(days=30)
        selected_30d = [
            item for item in history
            if (ts := _timestamp(item.get("timestamp"))) is not None and start_30d <= ts <= anchor
        ]
        complete_known = {key: set() for key in current}
        for item in selected_30d:
            for key, entries in _dimensions(item).items():
                complete_known[key].update(entries)
        for dimension, values in current.items():
            known = complete_known[dimension]
            for value in sorted(values - known):
                findings.append({
                    "schema_version": ANALYTICS_SCHEMA_VERSION,
                    "analytic_id": f"novel_{dimension}",
                    "title": labels[dimension],
                    "category": "novelty",
                    "classification": "derived_analytic",
                    "attribution": False,
                    "measurement": {"dimension": dimension, "value": value, "historical_occurrences": 0},
                    "baseline": {
                        "window": "30d",
                        "sample_count": long_window["sample_count"],
                        "minimum_samples": long_window["minimum_samples"],
                        "distinct_values": long_window["distinct"][dimension],
                    },
                    "evidence": [{"type": "event", "id": str(event.get("id") or "")[:128]}],
                    "explanation": (
                        f"The value was observed in the anchor event and did not occur in the bounded "
                        f"30-day baseline of {long_window['sample_count']} historical events. "
                        "This is novelty only, not maliciousness or attribution."
                    ),
                })
        command = _command(event)
        if command:
            command_history = [item for item in selected_30d if _command(item) == command]
            occurrences_30d = len(command_history)
            if occurrences_30d <= 1:
                findings.append({
                    "schema_version": ANALYTICS_SCHEMA_VERSION,
                    "analytic_id": "rare_command",
                    "title": "Rare command",
                    "category": "frequency",
                    "classification": "derived_analytic",
                    "attribution": False,
                    "measurement": {
                        "command": command[:256],
                        "historical_occurrences_30d": occurrences_30d,
                        "rare_at_or_below": 1,
                    },
                    "baseline": {
                        "window": "30d",
                        "sample_count": long_window["sample_count"],
                        "minimum_samples": long_window["minimum_samples"],
                    },
                    "evidence": (
                        [{"type": "event", "id": str(event.get("id") or "")[:128]}]
                        + [
                            {"type": "event", "id": str(item.get("id") or "")[:128]}
                            for item in command_history[:5] if item.get("id")
                        ]
                    ),
                    "explanation": (
                        f"The exact command occurred {occurrences_30d} time(s) in the 30-day historical "
                        "baseline. Rare means low observed frequency only, not maliciousness or attribution."
                    ),
                })

            start_24h = anchor - timedelta(hours=24)
            start_7d = anchor - timedelta(days=7)
            occurrences_24h = 1 + sum(
                1 for item in history
                if _command(item) == command
                and (ts := _timestamp(item.get("timestamp"))) is not None
                and start_24h <= ts <= anchor
            )
            occurrences_7d = sum(
                1 for item in history
                if _command(item) == command
                and (ts := _timestamp(item.get("timestamp"))) is not None
                and start_7d <= ts <= anchor
            )
            daily_average_7d = occurrences_7d / 7.0
            spike_threshold = max(5, int(daily_average_7d * 3 + 0.999999))
            if occurrences_24h >= spike_threshold:
                evidence = [
                    item for item in history
                    if _command(item) == command
                    and (ts := _timestamp(item.get("timestamp"))) is not None
                    and start_24h <= ts <= anchor
                ]
                findings.append({
                    "schema_version": ANALYTICS_SCHEMA_VERSION,
                    "analytic_id": "command_frequency_spike",
                    "title": "Command frequency spike",
                    "category": "frequency",
                    "classification": "derived_analytic",
                    "attribution": False,
                    "measurement": {
                        "command": command[:256],
                        "occurrences_24h": occurrences_24h,
                        "daily_average_7d": round(daily_average_7d, 3),
                        "threshold": spike_threshold,
                        "formula": "max(5, ceil(3 * seven_day_daily_average))",
                    },
                    "baseline": {
                        "window": "7d",
                        "sample_count": baseline["baseline_windows"]["7d"]["sample_count"],
                        "minimum_samples": baseline["baseline_windows"]["7d"]["minimum_samples"],
                    },
                    "evidence": (
                        [{"type": "event", "id": str(event.get("id") or "")[:128]}]
                        + [
                            {"type": "event", "id": str(item.get("id") or "")[:128]}
                            for item in evidence[:31] if item.get("id")
                        ]
                    ),
                    "explanation": (
                        f"The exact command occurred {occurrences_24h} time(s) in 24 hours versus a "
                        f"7-day daily average of {daily_average_7d:.3f}; the deterministic threshold was "
                        f"{spike_threshold}. This is a frequency change, not attribution."
                    ),
                })

        return {**baseline, "findings": findings}
