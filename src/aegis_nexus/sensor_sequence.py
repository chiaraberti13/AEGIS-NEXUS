"""Per-sensor monotonic delivery sequences used to detect telemetry gaps.

Every ``SensorClient`` process opens a random *stream* and numbers the events it
emits 1, 2, 3, ... inside the signed payload (``observed.sensor_sequence``).
Heartbeats report the highest sequence emitted so far, so losses at the tail of
a stream are visible too. The collector stores the received sequences as
compacted ranges, which makes gap accounting independent of arrival order:

    missing = highest sequence reported - distinct sequences received

A gap is disclosed evidence loss (collector down, rate limiting, rejected or
undeliverable events), never an inference about attacker behaviour. Retention
pruning of events does not change these counters.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

SEQUENCE_FIELD = "sensor_sequence"
STREAM_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
MAX_SEQUENCE = 2**53 - 1
MAX_RANGES_PER_STREAM = 256
MAX_STREAMS_PER_SENSOR = 32
MAX_REPORTED_GAPS = 10


class SensorSequenceError(ValueError):
    pass


def _sequence_number(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SensorSequenceError(f"{field} must be an integer")
    if not 1 <= value <= MAX_SEQUENCE:
        raise SensorSequenceError(f"{field} is out of range")
    return value


def _stream_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not STREAM_ID_PATTERN.fullmatch(value):
        raise SensorSequenceError(f"invalid {field}")
    return value


def validate_event_sequence(value: Any) -> dict[str, Any]:
    """Validate ``observed.sensor_sequence`` from an event payload."""
    if not isinstance(value, dict) or set(value) != {"stream_id", "sequence"}:
        raise SensorSequenceError("sensor_sequence must contain exactly stream_id and sequence")
    return {
        "stream_id": _stream_id(value["stream_id"], "sensor_sequence.stream_id"),
        "sequence": _sequence_number(value["sequence"], "sensor_sequence.sequence"),
    }


def validate_heartbeat_sequence(value: Any) -> dict[str, Any] | None:
    """Validate the optional ``event_sequence`` high-water mark in a heartbeat.

    ``last_sequence`` is 0 when the stream has not emitted any event yet.
    """
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"stream_id", "last_sequence"}:
        raise SensorSequenceError("event_sequence must contain exactly stream_id and last_sequence")
    last_sequence = value["last_sequence"]
    if last_sequence != 0:
        last_sequence = _sequence_number(last_sequence, "event_sequence.last_sequence")
    return {
        "stream_id": _stream_id(value["stream_id"], "event_sequence.stream_id"),
        "last_sequence": last_sequence,
    }


def _ensure_stream(conn: sqlite3.Connection, sensor_id: str, stream_id: str, now: str) -> None:
    conn.execute(
        """
        INSERT INTO sensor_sequence_streams(sensor_id,stream_id,first_seen_at,last_seen_at)
        VALUES(?,?,?,?)
        ON CONFLICT(sensor_id,stream_id) DO UPDATE SET last_seen_at=excluded.last_seen_at
        """,
        (sensor_id, stream_id, now, now),
    )
    stale = conn.execute(
        """
        SELECT stream_id FROM sensor_sequence_streams
        WHERE sensor_id=?
        ORDER BY last_seen_at DESC, stream_id DESC
        LIMIT -1 OFFSET ?
        """,
        (sensor_id, MAX_STREAMS_PER_SENSOR),
    ).fetchall()
    for row in stale:
        conn.execute(
            "DELETE FROM sensor_sequence_ranges WHERE sensor_id=? AND stream_id=?",
            (sensor_id, row[0]),
        )
        conn.execute(
            "DELETE FROM sensor_sequence_streams WHERE sensor_id=? AND stream_id=?",
            (sensor_id, row[0]),
        )


def record_event_sequence(
    conn: sqlite3.Connection,
    sensor_id: str,
    sequence: dict[str, Any],
    now: str,
) -> str:
    """Record one received event sequence inside the caller's ingest transaction.

    Returns ``received``, ``duplicate`` or ``untracked`` (range detail exhausted).
    """
    stream_id = sequence["stream_id"]
    number = int(sequence["sequence"])
    _ensure_stream(conn, sensor_id, stream_id, now)
    params = (sensor_id, stream_id)

    covering = conn.execute(
        """
        SELECT 1 FROM sensor_sequence_ranges
        WHERE sensor_id=? AND stream_id=? AND start_sequence<=? AND end_sequence>=?
        """,
        (*params, number, number),
    ).fetchone()
    if covering:
        conn.execute(
            "UPDATE sensor_sequence_streams SET duplicate_count=duplicate_count+1 WHERE sensor_id=? AND stream_id=?",
            params,
        )
        return "duplicate"

    left = conn.execute(
        "SELECT start_sequence FROM sensor_sequence_ranges WHERE sensor_id=? AND stream_id=? AND end_sequence=?",
        (*params, number - 1),
    ).fetchone()
    right = conn.execute(
        "SELECT end_sequence FROM sensor_sequence_ranges WHERE sensor_id=? AND stream_id=? AND start_sequence=?",
        (*params, number + 1),
    ).fetchone()
    outcome = "received"
    if left and right:
        conn.execute(
            "DELETE FROM sensor_sequence_ranges WHERE sensor_id=? AND stream_id=? AND start_sequence=?",
            (*params, number + 1),
        )
        conn.execute(
            "UPDATE sensor_sequence_ranges SET end_sequence=? WHERE sensor_id=? AND stream_id=? AND start_sequence=?",
            (right[0], *params, left[0]),
        )
    elif left:
        conn.execute(
            "UPDATE sensor_sequence_ranges SET end_sequence=? WHERE sensor_id=? AND stream_id=? AND start_sequence=?",
            (number, *params, left[0]),
        )
    elif right:
        conn.execute(
            "UPDATE sensor_sequence_ranges SET start_sequence=? WHERE sensor_id=? AND stream_id=? AND start_sequence=?",
            (number, *params, number + 1),
        )
    else:
        ranges = conn.execute(
            "SELECT COUNT(*) FROM sensor_sequence_ranges WHERE sensor_id=? AND stream_id=?",
            params,
        ).fetchone()[0]
        if ranges >= MAX_RANGES_PER_STREAM:
            # Bounded storage: keep counting, but disclose that duplicate detection
            # and gap detail are no longer exact for this stream.
            outcome = "untracked"
            conn.execute(
                "UPDATE sensor_sequence_streams SET detail_truncated=1 WHERE sensor_id=? AND stream_id=?",
                params,
            )
        else:
            conn.execute(
                "INSERT INTO sensor_sequence_ranges(sensor_id,stream_id,start_sequence,end_sequence) VALUES(?,?,?,?)",
                (*params, number, number),
            )

    conn.execute(
        """
        UPDATE sensor_sequence_streams
        SET received_count=received_count+1,
            max_received_sequence=MAX(max_received_sequence,?)
        WHERE sensor_id=? AND stream_id=?
        """,
        (number, *params),
    )
    return outcome


def record_heartbeat_sequence(
    conn: sqlite3.Connection,
    sensor_id: str,
    sequence: dict[str, Any],
    now: str,
) -> None:
    _ensure_stream(conn, sensor_id, sequence["stream_id"], now)
    conn.execute(
        """
        UPDATE sensor_sequence_streams
        SET max_reported_sequence=MAX(max_reported_sequence,?)
        WHERE sensor_id=? AND stream_id=?
        """,
        (int(sequence["last_sequence"]), sensor_id, sequence["stream_id"]),
    )


def _gaps(conn: sqlite3.Connection, sensor_id: str, stream_id: str, highest: int) -> list[dict[str, int]]:
    gaps: list[dict[str, int]] = []
    expected = 1
    for row in conn.execute(
        """
        SELECT start_sequence,end_sequence FROM sensor_sequence_ranges
        WHERE sensor_id=? AND stream_id=?
        ORDER BY start_sequence
        """,
        (sensor_id, stream_id),
    ):
        if row[0] > expected:
            gaps.append({"from": expected, "to": row[0] - 1})
            if len(gaps) >= MAX_REPORTED_GAPS:
                return gaps
        expected = max(expected, row[1] + 1)
    if highest >= expected and len(gaps) < MAX_REPORTED_GAPS:
        gaps.append({"from": expected, "to": highest})
    return gaps


def sequence_summary(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """Per-sensor gap accounting for the operations view."""
    summary: dict[str, dict[str, Any]] = {}
    rows = conn.execute(
        """
        SELECT * FROM sensor_sequence_streams
        ORDER BY sensor_id COLLATE NOCASE, last_seen_at DESC, stream_id DESC
        """
    ).fetchall()
    for row in rows:
        sensor_id = str(row["sensor_id"])
        highest = max(int(row["max_received_sequence"]), int(row["max_reported_sequence"]))
        # Duplicates never increment received_count, so it already counts distinct sequences.
        unique_received = int(row["received_count"])
        missing = max(0, highest - unique_received)
        item = summary.setdefault(
            sensor_id,
            {
                "streams": 0,
                "received": 0,
                "missing": 0,
                "duplicates": 0,
                "detail_truncated": False,
                "current_stream": None,
            },
        )
        item["streams"] += 1
        item["received"] += unique_received
        item["missing"] += missing
        item["duplicates"] += int(row["duplicate_count"])
        item["detail_truncated"] = item["detail_truncated"] or bool(row["detail_truncated"])
        if item["current_stream"] is None:
            item["current_stream"] = {
                "stream_id": str(row["stream_id"]),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "highest_sequence": highest,
                "received": unique_received,
                "missing": missing,
                "missing_ranges": _gaps(conn, sensor_id, str(row["stream_id"]), highest),
            }
    for item in summary.values():
        item["state"] = "gaps_detected" if item["missing"] else "complete"
    return summary
