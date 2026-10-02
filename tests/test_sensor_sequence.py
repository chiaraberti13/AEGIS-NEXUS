import json
import threading
import uuid
from datetime import datetime, timezone

import pytest

from aegis_nexus import sensor_sequence
from aegis_nexus.app import create_app
from aegis_nexus.model import EventValidationError, normalize_event
from aegis_nexus.sensors.client import MAX_EVENT_BYTES, SensorClient
from aegis_nexus.store import Store

STREAM = "stream-AAAAAAAAAAAAAAAAAAAA"
OTHER_STREAM = "stream-BBBBBBBBBBBBBBBBBBBB"


def _event(sequence, stream=STREAM, honeypot="ssh-decoy-01"):
    return normalize_event({
        "id": str(uuid.uuid4()),
        "honeypot": honeypot,
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.10",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "sensor_sequence": {"stream_id": stream, "sequence": sequence},
        },
    })


def _sequence_state(store, sensor_id="ssh-decoy-01"):
    telemetry = store.sensor_telemetry_observation()
    return next(item for item in telemetry["items"] if item["sensor_id"] == sensor_id)["event_sequence"]


@pytest.mark.parametrize(
    "value",
    [
        {"stream_id": STREAM, "sequence": 0},
        {"stream_id": STREAM, "sequence": -1},
        {"stream_id": STREAM, "sequence": True},
        {"stream_id": STREAM, "sequence": "7"},
        {"stream_id": STREAM, "sequence": 1.5},
        {"stream_id": STREAM, "sequence": sensor_sequence.MAX_SEQUENCE + 1},
        {"stream_id": "short", "sequence": 1},
        {"stream_id": "x" * 65, "sequence": 1},
        {"stream_id": "stream with spaces!!!!", "sequence": 1},
        {"stream_id": STREAM, "sequence": 1, "extra": "x"},
        {"sequence": 1},
        "not-an-object",
    ],
)
def test_malformed_sensor_sequence_is_rejected_not_coerced(value):
    with pytest.raises(EventValidationError):
        normalize_event({
            "honeypot": "ssh-decoy-01",
            "event_type": "connection",
            "observed": {"sensor_sequence": value},
        })


def test_in_order_delivery_reports_no_gap(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    for number in range(1, 6):
        store.ingest(_event(number))

    state = _sequence_state(store)
    assert state["state"] == "complete"
    assert state["received"] == 5
    assert state["missing"] == 0
    assert state["current_stream"]["highest_sequence"] == 5
    assert state["current_stream"]["missing_ranges"] == []


def test_out_of_order_delivery_only_counts_truly_missing_sequences(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    for number in (1, 3, 2, 6, 5, 9):
        store.ingest(_event(number))

    state = _sequence_state(store)
    assert state["state"] == "gaps_detected"
    assert state["received"] == 6
    assert state["missing"] == 3
    assert state["current_stream"]["missing_ranges"] == [{"from": 4, "to": 4}, {"from": 7, "to": 8}]

    store.ingest(_event(4))
    state = _sequence_state(store)
    assert state["missing"] == 2
    assert state["current_stream"]["missing_ranges"] == [{"from": 7, "to": 8}]


def test_heartbeat_high_water_reveals_loss_at_the_tail_of_a_stream(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.ingest(_event(1))
    store.ingest(_event(2))
    assert _sequence_state(store)["missing"] == 0

    store.record_sensor_heartbeat("ssh-decoy-01", event_sequence={"stream_id": STREAM, "last_sequence": 4})

    state = _sequence_state(store)
    assert state["missing"] == 2
    assert state["current_stream"]["missing_ranges"] == [{"from": 3, "to": 4}]


def test_heartbeat_before_any_event_is_not_a_gap(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.record_sensor_heartbeat("ssh-decoy-01", event_sequence={"stream_id": STREAM, "last_sequence": 0})

    state = _sequence_state(store)
    assert state["state"] == "complete"
    assert state["missing"] == 0


def test_duplicate_sequence_is_disclosed_and_cannot_hide_a_gap(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.ingest(_event(1))
    store.ingest(_event(3))
    store.ingest(_event(3))  # new event id, reused sequence number

    state = _sequence_state(store)
    assert state["duplicates"] == 1
    assert state["received"] == 2
    assert state["missing"] == 1
    assert state["current_stream"]["missing_ranges"] == [{"from": 2, "to": 2}]


def test_sensor_restart_opens_a_new_stream_instead_of_a_gap(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    for number in (1, 2, 3):
        store.ingest(_event(number, stream=STREAM))
    store.ingest(_event(1, stream=OTHER_STREAM))

    state = _sequence_state(store)
    assert state["streams"] == 2
    assert state["missing"] == 0
    assert state["received"] == 4
    assert state["current_stream"]["stream_id"] == OTHER_STREAM


def test_sequences_are_tracked_per_sensor(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.ingest(_event(1, honeypot="ssh-decoy-01"))
    store.ingest(_event(3, honeypot="web-decoy-01"))

    assert _sequence_state(store, "ssh-decoy-01")["missing"] == 0
    assert _sequence_state(store, "web-decoy-01")["missing"] == 2


def test_retention_pruning_does_not_rewrite_gap_accounting(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    saved = [store.ingest(_event(number)) for number in (1, 2, 4)]
    with store.connect() as conn:
        conn.execute("UPDATE events SET collector_received_at=?", ("2020-01-01T00:00:00+00:00",))
    assert store.prune(1) == len(saved)

    state = _sequence_state(store)
    assert state["received"] == 3
    assert state["missing"] == 1


def test_unsequenced_sources_are_labelled_not_counted_as_gaps(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    store.ingest(normalize_event({
        "honeypot": "suricata-01",
        "event_type": "ids_alert",
        "observed": {"source_ip": "203.0.113.11"},
    }))

    telemetry = store.sensor_telemetry_observation()
    item = next(entry for entry in telemetry["items"] if entry["sensor_id"] == "suricata-01")
    assert item["event_sequence"] == {"state": "unsequenced"}
    assert telemetry["sensors_with_sequence_gaps"] == 0
    assert telemetry["missing_sequenced_events"] == 0


def test_range_storage_is_bounded_and_truncation_is_disclosed(tmp_path, monkeypatch):
    monkeypatch.setattr(sensor_sequence, "MAX_RANGES_PER_STREAM", 3)
    store = Store(str(tmp_path / "aegis.db"))
    for number in (1, 3, 5, 7, 9):  # every arrival opens a new range
        store.ingest(_event(number))

    with store.connect() as conn:
        ranges = conn.execute("SELECT COUNT(*) FROM sensor_sequence_ranges").fetchone()[0]
    state = _sequence_state(store)
    assert ranges == 3
    assert state["detail_truncated"] is True
    assert state["received"] == 5
    assert state["missing"] == 4


def test_stream_history_per_sensor_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(sensor_sequence, "MAX_STREAMS_PER_SENSOR", 2)
    store = Store(str(tmp_path / "aegis.db"))
    for index in range(4):
        store.ingest(_event(1, stream=f"stream-{index:020d}"))

    with store.connect() as conn:
        streams = conn.execute("SELECT COUNT(*) FROM sensor_sequence_streams").fetchone()[0]
        orphan_ranges = conn.execute(
            """
            SELECT COUNT(*) FROM sensor_sequence_ranges r
            LEFT JOIN sensor_sequence_streams s USING(sensor_id, stream_id)
            WHERE s.sensor_id IS NULL
            """
        ).fetchone()[0]
    assert streams == 2
    assert orphan_ranges == 0


def _app(tmp_path):
    return create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "OPERATOR_API_KEY": "operator-secret",
        "SENSOR_KEYS": {"ssh-decoy-01": "ssh-secret"},
    })


def _post_event(client, sequence, observed_extra=None):
    observed = {
        "source_ip": "203.0.113.12",
        "service": "ssh",
        "protocol": "tcp",
        "destination_port": 22,
        "sensor_sequence": sequence,
        **(observed_extra or {}),
    }
    return client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "ssh-secret", "X-Aegis-Sensor": "ssh-decoy-01"},
        json={
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "honeypot": "ssh-decoy-01",
            "event_type": "connection",
            "observed": observed,
        },
    )


def test_api_rejects_malformed_sequence_and_reports_gaps_to_operators(tmp_path):
    client = _app(tmp_path).test_client()

    assert _post_event(client, {"stream_id": STREAM, "sequence": "1"}).status_code == 422
    assert _post_event(client, {"stream_id": STREAM, "sequence": 1}).status_code == 201
    assert _post_event(client, {"stream_id": STREAM, "sequence": 4}).status_code == 201

    status = client.get("/api/v1/operations/status", headers={"X-Aegis-Operator-Key": "operator-secret"})
    telemetry = status.get_json()["telemetry"]
    item = next(entry for entry in telemetry["items"] if entry["sensor_id"] == "ssh-decoy-01")
    assert item["event_sequence"]["missing"] == 2
    assert telemetry["sensors_with_sequence_gaps"] == 1
    assert telemetry["missing_sequenced_events"] == 2


def test_rejected_event_is_counted_as_evidence_loss_not_as_received(tmp_path):
    client = _app(tmp_path).test_client()
    assert _post_event(client, {"stream_id": STREAM, "sequence": 1}).status_code == 201
    rejected = _post_event(client, {"stream_id": STREAM, "sequence": 2}, {"source_ip": "not-an-ip"})
    assert rejected.status_code == 422
    assert _post_event(client, {"stream_id": STREAM, "sequence": 3}).status_code == 201

    status = client.get("/api/v1/operations/status", headers={"X-Aegis-Operator-Key": "operator-secret"})
    item = next(entry for entry in status.get_json()["telemetry"]["items"] if entry["sensor_id"] == "ssh-decoy-01")
    assert item["event_sequence"]["current_stream"]["missing_ranges"] == [{"from": 2, "to": 2}]


@pytest.mark.parametrize(
    "event_sequence",
    [
        {"stream_id": STREAM, "last_sequence": -1},
        {"stream_id": STREAM, "last_sequence": True},
        {"stream_id": "bad", "last_sequence": 1},
        {"stream_id": STREAM},
        [STREAM, 1],
    ],
)
def test_heartbeat_rejects_malformed_sequence_high_water(tmp_path, event_sequence):
    client = _app(tmp_path).test_client()
    response = client.post(
        "/api/v1/sensors/heartbeat",
        headers={"X-Aegis-Key": "ssh-secret", "X-Aegis-Sensor": "ssh-decoy-01"},
        json={"sensor_id": "ssh-decoy-01", "event_sequence": event_sequence},
    )
    assert response.status_code == 422
    assert response.get_json()["error"] == "invalid_event_sequence"


class _Response:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _capturing_client(monkeypatch):
    monkeypatch.setenv("AEGIS_SENSOR_API_KEY", "ssh-secret")
    sent = []
    lock = threading.Lock()

    def fake_urlopen(request, timeout):
        with lock:
            sent.append(json.loads(request.data))
        return _Response()

    monkeypatch.setattr("aegis_nexus.sensors.client.urllib.request.urlopen", fake_urlopen)
    return SensorClient("ssh-decoy-01"), sent


def test_sensor_client_numbers_events_and_reports_high_water(monkeypatch):
    client, sent = _capturing_client(monkeypatch)
    observed = {"source_ip": "203.0.113.13"}

    assert client.emit("connection", observed)
    assert client.emit("connection", observed)
    assert client.emit_heartbeat()

    first, second, heartbeat = sent
    assert "sensor_sequence" not in observed  # caller's dict is not mutated
    assert first["observed"]["sensor_sequence"] == {"stream_id": client.stream_id, "sequence": 1}
    assert second["observed"]["sensor_sequence"] == {"stream_id": client.stream_id, "sequence": 2}
    assert heartbeat["event_sequence"] == {"stream_id": client.stream_id, "last_sequence": 2}
    assert sensor_sequence.STREAM_ID_PATTERN.fullmatch(client.stream_id)


def test_locally_dropped_oversize_event_still_consumes_a_sequence(monkeypatch):
    client, sent = _capturing_client(monkeypatch)

    assert client.emit("command", {"command": "x" * (MAX_EVENT_BYTES + 1)}) is False
    assert client.emit("connection", {"source_ip": "203.0.113.14"})

    assert [event["observed"]["sensor_sequence"]["sequence"] for event in sent] == [2]


def test_concurrent_emits_get_unique_contiguous_sequences(monkeypatch):
    client, sent = _capturing_client(monkeypatch)
    threads = [threading.Thread(target=client.emit, args=("connection", {})) for _ in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(event["observed"]["sensor_sequence"]["sequence"] for event in sent) == list(range(1, 41))


def test_restarted_sensor_client_uses_a_new_stream(monkeypatch):
    monkeypatch.setenv("AEGIS_SENSOR_API_KEY", "ssh-secret")
    assert SensorClient("ssh-decoy-01").stream_id != SensorClient("ssh-decoy-01").stream_id
