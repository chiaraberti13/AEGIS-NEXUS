from __future__ import annotations

import json
import os
import time
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from ..security import sign_payload

MAX_EVENT_BYTES = 60_000


class SensorHeartbeat:
    def __init__(self, client: "SensorClient", interval_seconds: int):
        self.client = client
        self.interval_seconds = max(15, min(int(interval_seconds), 3600))
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"aegis-heartbeat-{client.honeypot}",
            daemon=True,
        )

    def _run(self) -> None:
        self.client.emit_heartbeat()
        while not self._stop.wait(self.interval_seconds):
            self.client.emit_heartbeat()

    def start(self) -> "SensorHeartbeat":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=min(2.0, float(self.client.timeout) + 0.25))


class SensorClient:
    def __init__(self, honeypot: str):
        self.honeypot = honeypot
        self.url = os.getenv("AEGIS_COLLECTOR_URL", "http://collector:8600/api/v1/events")
        self.key = os.getenv("AEGIS_SENSOR_API_KEY") or os.getenv("AEGIS_INGEST_API_KEY", "")
        self.timeout = float(os.getenv("AEGIS_SENSOR_TIMEOUT", "2.0"))
        self.sign_requests = os.getenv("AEGIS_SIGN_SENSOR_REQUESTS", "true").lower() in {"1", "true", "yes"}
        self.heartbeat_url = os.getenv(
            "AEGIS_HEARTBEAT_URL",
            self.url.rsplit("/api/v1/events", 1)[0] + "/api/v1/sensors/heartbeat"
            if self.url.endswith("/api/v1/events")
            else "http://collector:8600/api/v1/sensors/heartbeat",
        )
        self.heartbeat_interval = max(
            15,
            min(int(os.getenv("AEGIS_SENSOR_HEARTBEAT_INTERVAL_SECONDS", "60")), 3600),
        )

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

    def quarantine_artifact(
        self,
        data: bytes,
        *,
        original_name: str = "",
        content_type: str = "application/octet-stream",
    ) -> dict[str, Any] | None:
        if not self.key or not isinstance(data, bytes) or not data:
            return None
        base = self.url.rsplit("/api/v1/events", 1)[0] if self.url.endswith("/api/v1/events") else "http://collector:8600"
        url = base + "/api/v1/quarantine"
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Aegis-Key": self.key,
            "X-Aegis-Sensor": self.honeypot,
            "X-Aegis-Artifact-Name": str(original_name)[:255],
            "X-Aegis-Artifact-Type": str(content_type)[:128],
        }
        if self.sign_requests:
            timestamp = str(int(time.time()))
            headers["X-Aegis-Timestamp"] = timestamp
            headers["X-Aegis-Signature"] = sign_payload(self.key, timestamp, data)
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=max(self.timeout, 5.0)) as response:
                if not 200 <= response.status < 300:
                    return None
                payload = json.loads(response.read().decode("utf-8"))
                return payload if isinstance(payload, dict) else None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return None

    def emit_heartbeat(self) -> bool:
        if not self.key:
            return False
        payload_obj = {
            "sensor_id": self.honeypot,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        payload = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Aegis-Key": self.key,
            "X-Aegis-Sensor": self.honeypot,
        }
        if self.sign_requests:
            timestamp = str(int(time.time()))
            headers["X-Aegis-Timestamp"] = timestamp
            headers["X-Aegis-Signature"] = sign_payload(self.key, timestamp, payload)
        request = urllib.request.Request(self.heartbeat_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def start_heartbeat(self, interval_seconds: int | None = None) -> SensorHeartbeat:
        return SensorHeartbeat(
            self,
            self.heartbeat_interval if interval_seconds is None else interval_seconds,
        ).start()
