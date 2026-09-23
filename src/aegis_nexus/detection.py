from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


DETECTION_SCHEMA_VERSION = "1.1"


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
        return _finding(
            event,
            rule_id=self.id,
            rule_version=self.version,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            description=self.description,
            evidence=[event],
        )


def _observed(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("observed")
    return value if isinstance(value, dict) else {}


def _command_text(event: dict[str, Any]) -> str:
    value = _observed(event).get("command")
    return value.lower() if isinstance(value, str) else ""


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _source_ip(event: dict[str, Any]) -> str:
    return str(event.get("source_ip") or _observed(event).get("source_ip") or "")


def _credential(event: dict[str, Any]) -> dict[str, Any]:
    value = _observed(event).get("credential")
    return value if isinstance(value, dict) else {}


def _credential_fingerprint(event: dict[str, Any]) -> str:
    credential = _credential(event)
    if credential.get("password_complete") is False:
        return str(credential.get("sensor_reported_password_sha256") or "")
    return str(credential.get("password_sha256") or "")


def _path(event: dict[str, Any]) -> str:
    value = _observed(event).get("path")
    return str(value) if value is not None else ""


def _payload_text(event: dict[str, Any]) -> str:
    observed = _observed(event)
    values = [observed.get("path"), observed.get("payload")]
    return " ".join(str(value) for value in values if value is not None).lower()


def _destination_port(event: dict[str, Any]) -> int | None:
    value = event.get("destination_port")
    if value is None:
        value = _observed(event).get("destination_port")
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _service(event: dict[str, Any]) -> str:
    return str(event.get("service") or _observed(event).get("service") or "").lower()


def _event_id(event: dict[str, Any]) -> str:
    return str(event.get("id") or "")[:128]


def _dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in events:
        event_id = _event_id(item)
        if not event_id or event_id in seen:
            continue
        seen.add(event_id)
        result.append(item)
    return result


def _window(
    event: dict[str, Any],
    context: list[dict[str, Any]],
    seconds: int,
    *,
    same_source: bool = True,
) -> list[dict[str, Any]]:
    anchor = _parse_timestamp(event.get("timestamp"))
    if anchor is None:
        return [event]
    source = _source_ip(event)
    selected: list[dict[str, Any]] = []
    for item in _dedupe_events([*context, event]):
        timestamp = _parse_timestamp(item.get("timestamp"))
        if timestamp is None:
            continue
        age = (anchor - timestamp).total_seconds()
        if age < 0 or age > seconds:
            continue
        if same_source and source and _source_ip(item) != source:
            continue
        selected.append(item)
    selected.sort(key=lambda item: str(item.get("timestamp") or ""))
    return selected


def _finding(
    event: dict[str, Any],
    *,
    rule_id: str,
    rule_version: str,
    title: str,
    severity: str,
    confidence: int,
    description: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    refs = [{"type": "event", "id": _event_id(item)} for item in _dedupe_events(evidence) if _event_id(item)]
    return {
        "schema_version": DETECTION_SCHEMA_VERSION,
        "rule_id": rule_id,
        "rule_version": rule_version,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "source_ip": _source_ip(event) or None,
        "session_id": event.get("session_id"),
        "evidence": refs[:64],
    }


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

    def evaluate(
        self,
        event: dict[str, Any],
        context: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        history = context or []
        findings: list[dict[str, Any]] = []
        for rule in self.rules:
            finding = rule.evaluate(event)
            if finding:
                findings.append(finding)
        findings.extend(self._contextual_findings(event, history))
        return findings

    def _contextual_findings(
        self,
        event: dict[str, Any],
        context: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        source = _source_ip(event)
        if not source:
            return findings

        five_minutes = _window(event, context, 300)
        ten_minutes = _window(event, context, 600)
        two_minutes = _window(event, context, 120)

        auth_events = [item for item in five_minutes if item.get("event_type") == "credential"]
        if event.get("event_type") == "credential" and len(auth_events) >= 5:
            findings.append(_finding(
                event,
                rule_id="multiple_auth_failures",
                rule_version="1.0.0",
                title="Repeated authentication failures observed",
                severity="medium",
                confidence=95,
                description="Five or more credential attempts from the same source were observed within five minutes.",
                evidence=auth_events,
            ))

        brute_events = [item for item in ten_minutes if item.get("event_type") == "credential"]
        usernames = {str(_credential(item).get("username") or "") for item in brute_events}
        usernames.discard("")
        if event.get("event_type") == "credential" and len(brute_events) >= 10 and len(usernames) >= 5:
            findings.append(_finding(
                event,
                rule_id="credential_bruteforce",
                rule_version="1.0.0",
                title="Credential brute-force pattern observed",
                severity="high",
                confidence=90,
                description="Ten or more credential attempts covering at least five usernames were observed from the same source within ten minutes.",
                evidence=brute_events,
            ))

        fingerprint = _credential_fingerprint(event)
        if event.get("event_type") == "credential" and fingerprint:
            day = _window(event, context, 86400, same_source=False)
            reused = [item for item in day if _credential_fingerprint(item) == fingerprint]
            reuse_sources = {_source_ip(item) for item in reused if _source_ip(item)}
            if len(reused) >= 2 and len(reuse_sources) >= 2:
                findings.append(_finding(
                    event,
                    rule_id="credential_reuse",
                    rule_version="1.0.0",
                    title="Credential secret fingerprint reused across sources",
                    severity="medium",
                    confidence=90,
                    description="The same complete credential-secret fingerprint was observed from at least two source IPs within 24 hours. This is evidence of reuse, not actor attribution.",
                    evidence=reused,
                ))

        web_events = [
            item for item in five_minutes
            if item.get("event_type") in {"web.request", "web.payload", "credential"}
            and _service(item) in {"http", "https"}
        ]
        paths = {_path(item) for item in web_events if _path(item)}
        if event.get("event_type") in {"web.request", "web.payload", "credential"} and _service(event) in {"http", "https"} and len(paths) >= 8:
            findings.append(_finding(
                event,
                rule_id="web_scanning",
                rule_version="1.0.0",
                title="Web path scanning pattern observed",
                severity="medium",
                confidence=85,
                description="Eight or more distinct HTTP paths were observed from the same source within five minutes.",
                evidence=web_events,
            ))

        traversal_events = [
            item for item in five_minutes
            if any(marker in _payload_text(item) for marker in ("../", "..\\", "%2e%2e%2f", "%2e%2e%5c"))
        ]
        if any(marker in _payload_text(event) for marker in ("../", "..\\", "%2e%2e%2f", "%2e%2e%5c")) and len(traversal_events) >= 3:
            findings.append(_finding(
                event,
                rule_id="path_traversal_sequence",
                rule_version="1.0.0",
                title="Repeated path traversal sequence observed",
                severity="high",
                confidence=95,
                description="Three or more requests or payloads containing path-traversal evidence were observed from the same source within five minutes.",
                evidence=traversal_events,
            ))

        ports = {_destination_port(item) for item in two_minutes}
        ports.discard(None)
        if len(ports) >= 5:
            findings.append(_finding(
                event,
                rule_id="rapid_port_sequence",
                rule_version="1.0.0",
                title="Rapid multi-port sequence observed",
                severity="medium",
                confidence=90,
                description="Five or more distinct destination ports were observed from the same source within two minutes.",
                evidence=two_minutes,
            ))

        services = {_service(item) for item in five_minutes if _service(item)}
        recon_ports = {_destination_port(item) for item in five_minutes}
        recon_ports.discard(None)
        if len(five_minutes) >= 15 and (len(services) >= 3 or len(recon_ports) >= 5):
            findings.append(_finding(
                event,
                rule_id="recon_burst",
                rule_version="1.0.0",
                title="Reconnaissance burst observed",
                severity="medium",
                confidence=85,
                description="At least fifteen events with multi-service or multi-port breadth were observed from the same source within five minutes.",
                evidence=five_minutes,
            ))

        return findings
