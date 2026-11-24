"""Collector-only outbound forwarding of events and alerts to a SIEM.

Design constraints (Cycle K):

- **Fail-closed.** Forwarding is disabled unless explicitly configured. A
  webhook without a signing secret is refused at construction, so the collector
  never emits unsigned telemetry.
- **Never block ingestion.** ``submit`` enqueues without blocking; when the
  bounded queue is full the record is dropped and counted as evidence loss, so a
  slow or unreachable SIEM can never stall the ingest hot path.
- **Bounded.** The queue has a hard size cap; delivery uses bounded retries.
- **Provenance preserved.** The forwarded envelope wraps the stored record,
  which keeps its own observed/enrichment/derived/hypotheses classes and the
  collector normalization (Evidence Integrity) metadata.
- **Collector only.** This module is imported by the collector app, never by a
  sensor. Sensors gain no outbound path from forwarding.
"""

from __future__ import annotations

import json
import queue
import socket
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import urlparse

from .security import sign_payload

FORWARD_SCHEMA_VERSION = "1.0"
_MAX_MESSAGE_BYTES = 65536
_QUEUE_MAX_CAP = 100000
_SENTINEL = object()


class ForwardingError(ValueError):
    """Raised for fail-closed misconfiguration of the forwarder."""


class ForwardingSink(Protocol):
    name: str

    def send(self, envelope: dict[str, Any]) -> None:
        """Deliver one envelope or raise on failure."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SyslogSink:
    """RFC 5424 syslog sink over UDP or TCP (octet-counting framing)."""

    host: str
    port: int = 514
    protocol: str = "udp"
    facility: int = 17  # local1
    severity: int = 6  # informational
    timeout: float = 5.0
    name: str = field(default="syslog", init=False)

    def __post_init__(self) -> None:
        if self.protocol not in {"udp", "tcp"}:
            raise ForwardingError("syslog protocol must be udp or tcp")
        if not self.host:
            raise ForwardingError("syslog host is required")

    def _frame(self, envelope: dict[str, Any]) -> bytes:
        pri = self.facility * 8 + self.severity
        body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
        header = f"<{pri}>1 {_now()} aegis-nexus collector - {envelope.get('kind', '-')} - "
        message = (header + body).encode("utf-8", "replace")[:_MAX_MESSAGE_BYTES]
        return message

    def send(self, envelope: dict[str, Any]) -> None:
        message = self._frame(envelope)
        if self.protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(message, (self.host, self.port))
        else:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                # RFC 6587 octet-counting framing for stream transport.
                sock.sendall(f"{len(message)} ".encode("ascii") + message)


@dataclass
class WebhookSink:
    """Signed JSON webhook sink (HMAC-SHA256 over the serialized envelope)."""

    url: str
    secret: str
    timeout: float = 5.0
    name: str = field(default="webhook", init=False)

    def __post_init__(self) -> None:
        if not self.secret:
            # Fail closed: never emit unsigned telemetry.
            raise ForwardingError("webhook forwarding requires a signing secret")
        scheme = urlparse(self.url).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ForwardingError("webhook url must be http(s)")

    def send(self, envelope: dict[str, Any]) -> None:
        body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        timestamp = _now()
        signature = sign_payload(self.secret, timestamp, body)
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Aegis-Timestamp": timestamp,
                "X-Aegis-Signature": signature,
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - scheme validated
            response.read(1)


class EventForwarder:
    """Bounded, non-blocking, collector-only forwarder with a worker thread."""

    def __init__(
        self,
        sinks: list[ForwardingSink],
        *,
        queue_max: int = 1000,
        max_retries: int = 3,
        logger: Any | None = None,
    ) -> None:
        self.sinks = list(sinks)
        self.enabled = bool(self.sinks)
        self.max_retries = max(1, min(int(max_retries), 10))
        capacity = max(1, min(int(queue_max), _QUEUE_MAX_CAP))
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=capacity)
        self._logger = logger
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        self._metrics = {"submitted": 0, "delivered": 0, "dropped": 0, "failed": 0}

    # -- public API ---------------------------------------------------------
    def submit(self, kind: str, record: dict[str, Any]) -> bool:
        """Enqueue a record without blocking. Returns False if dropped."""
        if not self.enabled:
            return False
        envelope = {
            "schema_version": FORWARD_SCHEMA_VERSION,
            "kind": str(kind)[:32],
            "forwarded_at": _now(),
            "source": "aegis-nexus-collector",
            "record": record,
        }
        try:
            self._queue.put_nowait(envelope)
        except queue.Full:
            with self._lock:
                self._metrics["dropped"] += 1
            self._log("forwarding queue full; record dropped (evidence loss)")
            return False
        with self._lock:
            self._metrics["submitted"] += 1
        return True

    def start(self) -> None:
        if not self.enabled or self._worker is not None:
            return
        self._worker = threading.Thread(target=self._run, name="aegis-forwarder", daemon=True)
        self._worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._worker is None:
            return
        self._queue.put(_SENTINEL)
        self._worker.join(timeout=timeout)
        self._worker = None

    def drain(self) -> None:
        """Synchronously deliver everything currently queued (used in tests)."""
        while True:
            try:
                envelope = self._queue.get_nowait()
            except queue.Empty:
                return
            if envelope is _SENTINEL:
                continue
            self._deliver(envelope)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            snapshot = dict(self._metrics)
        snapshot["enabled"] = self.enabled
        snapshot["queued"] = self._queue.qsize()
        snapshot["sinks"] = [sink.name for sink in self.sinks]
        return snapshot

    # -- internals ----------------------------------------------------------
    def _run(self) -> None:
        while True:
            envelope = self._queue.get()
            if envelope is _SENTINEL:
                self._queue.task_done()
                return
            self._deliver(envelope)
            self._queue.task_done()

    def _deliver(self, envelope: dict[str, Any]) -> None:
        for sink in self.sinks:
            delivered = False
            for _ in range(self.max_retries):
                try:
                    sink.send(envelope)
                    delivered = True
                    break
                except (OSError, urllib.error.URLError, ValueError):
                    continue
            with self._lock:
                if delivered:
                    self._metrics["delivered"] += 1
                else:
                    self._metrics["failed"] += 1
            if not delivered:
                self._log(f"forwarding sink '{sink.name}' failed after retries")

    def _log(self, message: str) -> None:
        if self._logger is not None:
            try:
                self._logger.warning("aegis-forwarding: %s", message)
            except Exception:
                pass


def build_forwarder(config: dict[str, Any], *, logger: Any | None = None) -> EventForwarder:
    """Construct a forwarder from an ``AEGIS_FORWARD_*`` configuration mapping.

    Fail-closed: when forwarding is not enabled, or enabled without any sink, the
    returned forwarder is inert (``enabled`` False) and never opens a socket.
    """
    if not config.get("FORWARDING_ENABLED"):
        return EventForwarder([], logger=logger)

    sinks: list[ForwardingSink] = []
    syslog_host = str(config.get("FORWARD_SYSLOG_HOST") or "").strip()
    if syslog_host:
        sinks.append(
            SyslogSink(
                host=syslog_host,
                port=int(config.get("FORWARD_SYSLOG_PORT") or 514),
                protocol=str(config.get("FORWARD_SYSLOG_PROTOCOL") or "udp").lower(),
            )
        )
    webhook_url = str(config.get("FORWARD_WEBHOOK_URL") or "").strip()
    if webhook_url:
        sinks.append(
            WebhookSink(
                url=webhook_url,
                secret=str(config.get("FORWARD_WEBHOOK_SECRET") or ""),
            )
        )

    return EventForwarder(
        sinks,
        queue_max=int(config.get("FORWARD_QUEUE_MAX") or 1000),
        max_retries=int(config.get("FORWARD_MAX_RETRIES") or 3),
        logger=logger,
    )
