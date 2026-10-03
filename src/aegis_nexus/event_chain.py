"""Tamper-evident hash chain over stored events.

Every stored event gets a monotonic ``chain_seq``, the ``prev_hash`` of the
previous chained record and its own ``record_hash``: SHA-256 over the exact
stored column text plus ``prev_hash``. Editing or deleting a record in the
middle of the chain, or reordering records, breaks verification at that point.
Retention and capacity pruning legitimately remove the *oldest* records, so the
first surviving record is accepted as the chain anchor and reported as
``pruned_before``. Records stored before the chain existed carry no chain
fields and are reported as ``unchained_legacy``, never silently trusted.

The chain detects accidental corruption and partial tampering. An attacker who
can rewrite the whole database can also rebuild the chain; export
``head_hash`` off-host to defend against that.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

CHAIN_VERSION = 1
GENESIS_HASH = "0" * 64
HEAD_ID = 1

# Columns covered by record_hash, in a fixed order. JSON columns are hashed as
# stored text so verification never depends on re-serialization.
HASHED_COLUMNS = (
    "id", "timestamp", "collector_received_at", "honeypot", "event_type", "severity",
    "source_ip", "session_id", "schema_version", "observed", "enrichment", "derived",
    "hypotheses", "collector",
)


def compute_record_hash(chain_seq: int, prev_hash: str, values: dict[str, Any]) -> str:
    payload = [CHAIN_VERSION, int(chain_seq), prev_hash] + [values.get(name) for name in HASHED_COLUMNS]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append_record(conn: sqlite3.Connection, values: dict[str, Any]) -> tuple[int, str]:
    """Chain a freshly inserted event row. Caller must hold the write lock (BEGIN IMMEDIATE)."""
    head = conn.execute("SELECT last_seq,last_hash FROM event_chain_head WHERE id=?", (HEAD_ID,)).fetchone()
    prev_seq, prev_hash = (int(head[0]), str(head[1])) if head else (0, GENESIS_HASH)
    seq = prev_seq + 1
    record_hash = compute_record_hash(seq, prev_hash, values)
    conn.execute(
        "UPDATE events SET chain_seq=?, prev_hash=?, record_hash=? WHERE id=?",
        (seq, prev_hash, record_hash, values["id"]),
    )
    conn.execute(
        "INSERT INTO event_chain_head(id,last_seq,last_hash) VALUES(?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET last_seq=excluded.last_seq, last_hash=excluded.last_hash",
        (HEAD_ID, seq, record_hash),
    )
    return seq, record_hash


def verify_chain(conn: sqlite3.Connection, *, max_problems: int = 20) -> dict[str, Any]:
    """Walk the chain in order and report integrity. Read-only and streaming."""
    problems: list[dict[str, Any]] = []
    truncated = False

    def problem(kind: str, **detail: Any) -> None:
        nonlocal truncated
        if len(problems) < max_problems:
            problems.append({"type": kind, **detail})
        else:
            truncated = True

    legacy = int(conn.execute("SELECT COUNT(*) FROM events WHERE chain_seq IS NULL").fetchone()[0])
    columns = ", ".join(HASHED_COLUMNS)
    cursor = conn.execute(
        f"SELECT chain_seq, prev_hash, record_hash, {columns} FROM events "
        "WHERE chain_seq IS NOT NULL ORDER BY chain_seq ASC"
    )
    verified = 0
    first_seq: int | None = None
    last_seq: int | None = None
    last_hash: str | None = None
    for row in cursor:
        seq = int(row[0])
        stored_prev, stored_hash = row[1], row[2]
        values = dict(zip(HASHED_COLUMNS, row[3:]))
        if first_seq is None:
            first_seq = seq  # anchor: older records may have been pruned by retention
        else:
            if seq != (last_seq or 0) + 1:
                problem("sequence_gap", after=last_seq, found=seq)
            if stored_prev != last_hash:
                problem("broken_link", chain_seq=seq, event_id=values["id"])
        expected = compute_record_hash(seq, str(stored_prev), values)
        if expected != stored_hash:
            problem("record_hash_mismatch", chain_seq=seq, event_id=values["id"])
        else:
            verified += 1
        last_seq, last_hash = seq, stored_hash

    head = conn.execute("SELECT last_seq,last_hash FROM event_chain_head WHERE id=?", (HEAD_ID,)).fetchone()
    if head is None:
        if last_seq is not None:
            problem("head_missing")
    elif int(head[0]) != (last_seq or 0) or (last_seq is not None and str(head[1]) != last_hash):
        problem("head_mismatch", head_seq=int(head[0]), last_seq=last_seq)

    return {
        "chain_version": CHAIN_VERSION,
        "ok": not problems,
        "records_verified": verified,
        "unchained_legacy": legacy,
        "pruned_before": first_seq if first_seq and first_seq > 1 else None,
        "head_seq": int(head[0]) if head else 0,
        "head_hash": str(head[1]) if head else GENESIS_HASH,
        "problems": problems,
        "problems_truncated": truncated,
    }
