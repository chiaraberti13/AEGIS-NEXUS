from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from ..security import sign_payload

MAX_EVENT_BYTES = 60_000


class SensorClient:
    def __init__(self, honeypot: str):
        self.honeypot = honeypot
        self.url = os.getenv("AEGIS_COLLECTOR_URL", "http://collector:8600/api/v1/events")
        self.key = os.getenv("AEGIS_SENSOR_API_KEY") or os.getenv("AEGIS_INGEST_API_KEY", "")
        self.timeout = float(os.getenv("AEGIS_SENSOR_TIMEOUT", "2.0"))
        self.sign_requests = os.getenv("AEGIS_SIGN_SENSOR_REQUESTS", "true").lower() in {"1", "true", "yes"}

    def emit(self, event_type: str, observed: dict[str, Any], severity: str = "info", derived: dict[str, Any] | None = None) -> bool:
        if not self.key:
            return False
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "honeypot": self.honeypot,
            "event_type": event_type,
            "severity": severity,
            "observed": observed,
            "derived": derived or {},
            "enrichment": {},
            "hypotheses": [],
        }
        payload = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
        if len(payload) > MAX_EVENT_BYTES:
            return False
        headers = {
            "Content-Type": "application/json",
            "X-Aegis-Key": self.key,
            "X-Aegis-Sensor": self.honeypot,
        }
        if self.sign_requests:
            timestamp = str(int(time.time()))
            headers["X-Aegis-Timestamp"] = timestamp
            headers["X-Aegis-Signature"] = sign_payload(self.key, timestamp, payload)
        request = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
