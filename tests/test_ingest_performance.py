"""Ingest hot-path micro-benchmark (Cross-cutting: ingest performance bound).

`normalize_event` runs once per ingested event and is the per-event CPU hot
path (bounded, hostile-input-safe normalization into the four provenance
classes). This benchmark guards against a *gross* performance regression on
that path — it is deliberately not a precise micro-benchmark, so it stays
stable on shared/slow CI machines: the bound is generous (orders of magnitude
above the real cost) and only catches a catastrophic regression (e.g. an
accidental O(n^2) or a per-event network/disk call sneaking into normalization).

Documented bound: normalize_event must stay well under 5 ms/event on the hot
path. Typical cost is tens of microseconds; the margin is intentional.
"""

from __future__ import annotations

import time

from aegis_nexus.model import normalize_event

_HOT_PATH_BOUND_MS = 5.0
_ITERATIONS = 2000


def _representative_payload() -> dict:
    # A representative command event with observed network evidence, a captured
    # credential and a derived MITRE mapping with rationale+evidence — i.e. all
    # four provenance classes exercised, not a trivial empty event.
    return {
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": "medium",
        "observed": {
            "source_ip": "203.0.113.9",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
            "command": "cat /etc/passwd",
            "credential": {"username": "root", "password": "hunter2"},
        },
        "enrichment": {
            "geoip": {"source": "local-geoip", "observed_at": "2026-11-26T00:00:00Z",
                      "country": "US", "asn": "AS64500"},
        },
        "derived": {
            "mitre": [{"technique_id": "T1003", "rationale": "credential store access",
                       "evidence": ["observed.command"]}],
        },
    }


def test_normalize_event_hot_path_throughput_within_bound():
    payload = _representative_payload()
    # Warm up (import/JIT-free Python, but primes caches/branch predictors).
    for _ in range(50):
        normalize_event(dict(payload))

    start = time.perf_counter()
    for _ in range(_ITERATIONS):
        event = normalize_event(dict(payload))
    elapsed = time.perf_counter() - start

    per_event_ms = (elapsed / _ITERATIONS) * 1000.0
    # Sanity: normalization produced the four provenance classes.
    assert event["observed"]["command"] == "cat /etc/passwd"
    assert "enrichment" in event and "derived" in event and "hypotheses" in event
    assert per_event_ms < _HOT_PATH_BOUND_MS, (
        f"normalize_event hot path {per_event_ms:.3f} ms/event exceeds the "
        f"{_HOT_PATH_BOUND_MS} ms/event regression bound"
    )
