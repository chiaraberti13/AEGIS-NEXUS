from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


DETECTION_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class DetectionRule:
    id: str
    version: str
    title: str
    severity: str
    confidence: int
    description: str
    matcher: Callable[[dict[str, Any]], bool]

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if not self.matcher(event):
            return None
        return {
            "schema_version": DETECTION_SCHEMA_VERSION,
            "rule_id": self.id,
            "rule_version": self.version,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": event.get("source_ip") or (event.get("observed") or {}).get("source_ip"),
            "session_id": event.get("session_id"),
            "evidence": [{"type": "event", "id": event["id"]}],
        }


def _observed(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("observed")
    return value if isinstance(value, dict) else {}


def _command_text(event: dict[str, Any]) -> str:
    value = _observed(event).get("command")
    return value.lower() if isinstance(value, str) else ""


def _is_download_attempt(event: dict[str, Any]) -> bool:
    command = _command_text(event)
    return any(token in command for token in ("wget ", "curl ", "powershell ", "invoke-webrequest", "certutil "))


def _is_command_staging(event: dict[str, Any]) -> bool:
    command = _command_text(event)
    markers = ("chmod +x", "base64 -d", "base64 --decode", "python -c", "python3 -c", "sh -c", "bash -c")
    return any(marker in command for marker in markers)


def _is_high_suricata(event: dict[str, Any]) -> bool:
    if event.get("event_type") != "ids.alert":
        return False
    alert = _observed(event).get("alert")
    if not isinstance(alert, dict):
        return False
    try:
        # Suricata severity 1 is the highest priority; 2 is also operationally significant.
        return int(alert.get("severity")) <= 2
    except (TypeError, ValueError):
        return False


BUILTIN_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        id="download_attempt",
        version="1.0.0",
        title="Payload download command observed",
        severity="medium",
        confidence=90,
        description="A captured command contains a commonly used file-download utility or primitive.",
        matcher=_is_download_attempt,
    ),
    DetectionRule(
        id="command_staging_detected",
        version="1.0.0",
        title="Command staging behavior observed",
        severity="high",
        confidence=85,
        description="A captured command contains an execution or decoding primitive commonly used during staging.",
        matcher=_is_command_staging,
    ),
    DetectionRule(
        id="suricata_high_severity",
        version="1.0.0",
        title="High-severity Suricata alert observed",
        severity="high",
        confidence=95,
        description="Observed Suricata telemetry reports severity 1 or 2. This preserves IDS evidence without adding attribution.",
        matcher=_is_high_suricata,
    ),
)


class DetectionEngine:
    def __init__(self, rules: tuple[DetectionRule, ...] = BUILTIN_RULES):
        self.rules = rules

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for rule in self.rules:
            finding = rule.evaluate(event)
            if finding:
                findings.append(finding)
        return findings
