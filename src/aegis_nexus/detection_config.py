from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

RULE_DEFAULTS: dict[str, dict[str, Any]] = {
    "download_attempt": {"enabled": True, "thresholds": {}},
    "command_staging_detected": {"enabled": True, "thresholds": {}},
    "suricata_high_severity": {"enabled": True, "thresholds": {}},
    "honeytoken_reuse": {"enabled": True, "thresholds": {}},
    "multiple_auth_failures": {"enabled": True, "thresholds": {"attempts": 5, "window_seconds": 300}},
    "credential_bruteforce": {"enabled": True, "thresholds": {"attempts": 10, "usernames": 5, "window_seconds": 600}},
    "credential_reuse": {"enabled": True, "thresholds": {"events": 2, "sources": 2, "window_seconds": 86400}},
    "web_scanning": {"enabled": True, "thresholds": {"paths": 8, "window_seconds": 300}},
    "path_traversal_sequence": {"enabled": True, "thresholds": {"events": 3, "window_seconds": 300}},
    "rapid_port_sequence": {"enabled": True, "thresholds": {"ports": 5, "window_seconds": 120}},
    "recon_burst": {"enabled": True, "thresholds": {"events": 15, "services": 3, "ports": 5, "window_seconds": 300}},
}

_THRESHOLD_LIMITS = {
    "attempts": (2, 10000),
    "usernames": (2, 10000),
    "events": (2, 10000),
    "sources": (2, 10000),
    "paths": (2, 10000),
    "ports": (2, 65535),
    "services": (2, 10000),
    "window_seconds": (30, 86400),
}


class DetectionConfigError(ValueError):
    pass


@dataclass(frozen=True)
class DetectionConfig:
    rules: dict[str, dict[str, Any]]

    @classmethod
    def defaults(cls) -> "DetectionConfig":
        return cls(deepcopy(RULE_DEFAULTS))

    @classmethod
    def from_json(cls, raw: str | None) -> "DetectionConfig":
        if not raw or not raw.strip():
            return cls.defaults()
        if len(raw.encode("utf-8")) > 65536:
            raise DetectionConfigError("detection_config_too_large")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DetectionConfigError("invalid_detection_config_json") from exc
        if not isinstance(payload, dict) or set(payload) - {"rules"}:
            raise DetectionConfigError("detection_config_requires_rules_object")
        overrides = payload.get("rules")
        if not isinstance(overrides, dict):
            raise DetectionConfigError("detection_config_rules_must_be_object")

        result = deepcopy(RULE_DEFAULTS)
        for rule_id, override in overrides.items():
            if rule_id not in result:
                raise DetectionConfigError(f"unknown_detection_rule:{rule_id}")
            if not isinstance(override, dict) or set(override) - {"enabled", "thresholds"}:
                raise DetectionConfigError(f"invalid_detection_rule_config:{rule_id}")
            if "enabled" in override:
                if not isinstance(override["enabled"], bool):
                    raise DetectionConfigError(f"invalid_detection_rule_enabled:{rule_id}")
                result[rule_id]["enabled"] = override["enabled"]
            if "thresholds" in override:
                thresholds = override["thresholds"]
                if not isinstance(thresholds, dict):
                    raise DetectionConfigError(f"invalid_detection_thresholds:{rule_id}")
                allowed = set(result[rule_id]["thresholds"])
                unknown = set(thresholds) - allowed
                if unknown:
                    raise DetectionConfigError(f"unknown_detection_threshold:{rule_id}:{sorted(unknown)[0]}")
                for key, value in thresholds.items():
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise DetectionConfigError(f"invalid_detection_threshold:{rule_id}:{key}")
                    minimum, maximum = _THRESHOLD_LIMITS[key]
                    if not minimum <= value <= maximum:
                        raise DetectionConfigError(f"detection_threshold_out_of_range:{rule_id}:{key}")
                    result[rule_id]["thresholds"][key] = value
        return cls(result)

    def enabled(self, rule_id: str) -> bool:
        return bool(self.rules.get(rule_id, {}).get("enabled", False))

    def threshold(self, rule_id: str, key: str) -> int:
        try:
            return int(self.rules[rule_id]["thresholds"][key])
        except (KeyError, TypeError, ValueError) as exc:
            raise DetectionConfigError(f"missing_detection_threshold:{rule_id}:{key}") from exc

    def public(self) -> dict[str, Any]:
        return {"rules": deepcopy(self.rules)}
