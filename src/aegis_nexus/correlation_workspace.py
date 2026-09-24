from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from .correlation import parse_ts


CORRELATION_SCHEMA_VERSION = "1.0"

_FEATURES: dict[str, tuple[float, str]] = {
    "source_ip": (0.90, "observed.source_ip"),
    "credential_secret_fingerprint": (0.85, "derived.credential_secret_fingerprint"),
    "command_sha256": (0.85, "derived.command_sha256"),
    "payload_sha256": (0.85, "derived.payload_sha256"),
    "ioc": (0.80, "derived.ioc"),
    "suricata_signature": (0.75, "observed.alert.signature"),
    "username": (0.65, "observed.credential.username"),
    "asn": (0.45, "enrichment.asn"),
    "service": (0.25, "observed.service"),
    "destination_port": (0.20, "observed.destination_port"),
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _credential_fingerprint(credential: dict[str, Any]) -> str | None:
    complete = credential.get("password_complete") is not False
    if not complete and credential.get("sensor_reported_password_sha256"):
        digest = str(credential["sensor_reported_password_sha256"]).strip().lower()
        return f"sha256:{digest}" if digest else None
    digest = str(credential.get("password_sha256") or "").strip().lower()
    return f"sha256:{digest}" if digest else None


def _safe_basis_value(kind: str, value: str) -> str:
    if kind in {"command_sha256", "payload_sha256", "credential_secret_fingerprint"}:
        return value[:80]
    return value[:180]


class CorrelationWorkspace:
    """Bounded, deterministic cross-session correlation for investigation pivots."""

    def __init__(self, path: str, max_events: int = 20_000):
        self.path = path
        self.max_events = max(100, min(int(max_events), 100_000))
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _add(
        features: dict[str, dict[str, set[str]]],
        kind: str,
        value: Any,
        event_id: str,
    ) -> None:
        if kind not in _FEATURES or value in (None, ""):
            return
        clean = str(value)[:512]
        if not clean:
            return
        features[kind][clean].add(event_id)

    def _features(self, rows: list[sqlite3.Row]) -> dict[str, dict[str, set[str]]]:
        features: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        for row in rows:
            event_id = str(row["id"])
            observed = _json_object(row["observed"])
            derived = _json_object(row["derived"])

            self._add(features, "source_ip", row["source_ip"], event_id)
            self._add(features, "asn", row["asn"], event_id)
            self._add(features, "service", row["service"], event_id)
            self._add(features, "destination_port", row["destination_port"], event_id)

            credential = observed.get("credential")
            if isinstance(credential, dict):
                self._add(features, "username", credential.get("username"), event_id)
                self._add(
                    features,
                    "credential_secret_fingerprint",
                    _credential_fingerprint(credential),
                    event_id,
                )

            command = observed.get("command")
            if command not in (None, ""):
                self._add(features, "command_sha256", "sha256:" + _sha256(str(command)), event_id)
            payload = observed.get("payload")
            if payload not in (None, ""):
                self._add(features, "payload_sha256", "sha256:" + _sha256(str(payload)), event_id)

            alert = observed.get("alert")
            if isinstance(alert, dict):
                self._add(features, "suricata_signature", alert.get("signature"), event_id)
            elif observed.get("signature"):
                self._add(features, "suricata_signature", observed.get("signature"), event_id)

            iocs = derived.get("ioc")
            if isinstance(iocs, list):
                for item in iocs[:128]:
                    if not isinstance(item, dict):
                        continue
                    ioc_type = str(item.get("type") or "")[:64]
                    ioc_value = str(item.get("value") or "")[:384]
                    if ioc_type and ioc_value:
                        self._add(features, "ioc", f"{ioc_type}:{ioc_value}", event_id)
        return features

    @staticmethod
    def _score(matches: list[dict[str, Any]]) -> float:
        # Repeated values from one feature family add evidence detail, not extra score.
        by_feature: dict[str, float] = {}
        for match in matches:
            feature = str(match["feature"])
            by_feature[feature] = max(by_feature.get(feature, 0.0), float(match["weight"]))
        remaining = 1.0
        for weight in by_feature.values():
            remaining *= 1.0 - weight
        return round(min(1.0, 1.0 - remaining), 3)

    @staticmethod
    def _strength(score: float) -> str:
        if score >= 0.85:
            return "strong"
        if score >= 0.65:
            return "moderate"
        return "weak"

    def analyze(
        self,
        session_id: str,
        *,
        hours: int = 720,
        limit: int = 50,
        min_score: float = 0.50,
    ) -> dict[str, Any] | None:
        clean_session_id = str(session_id)[:128]
        bounded_hours = max(1, min(int(hours), 24 * 365))
        bounded_limit = max(1, min(int(limit), 200))
        bounded_min_score = max(0.0, min(float(min_score), 1.0))

        with self.connect() as conn:
            target_rows = conn.execute(
                """
                SELECT id,timestamp,source_ip,session_id,honeypot,service,destination_port,asn,observed,derived
                FROM events WHERE session_id=? ORDER BY timestamp ASC,id ASC
                """,
                (clean_session_id,),
            ).fetchall()
            if not target_rows:
                return None

            anchor = parse_ts(str(target_rows[-1]["timestamp"]))
            since = (anchor - timedelta(hours=bounded_hours)).isoformat()
            until = (anchor + timedelta(hours=bounded_hours)).isoformat()
            candidate_rows = conn.execute(
                """
                SELECT id,timestamp,source_ip,session_id,honeypot,service,destination_port,asn,observed,derived
                FROM events
                WHERE session_id!=? AND timestamp>=? AND timestamp<=?
                ORDER BY timestamp DESC,id DESC
                LIMIT ?
                """,
                (clean_session_id, since, until, self.max_events + 1),
            ).fetchall()

        truncated = len(candidate_rows) > self.max_events
        candidate_rows = list(candidate_rows[:self.max_events])
        target_features = self._features(list(target_rows))

        grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in candidate_rows:
            grouped[str(row["session_id"])].append(row)

        correlations: list[dict[str, Any]] = []
        for candidate_session_id, rows in grouped.items():
            candidate_features = self._features(rows)
            matches: list[dict[str, Any]] = []
            for kind, (weight, basis) in _FEATURES.items():
                shared = set(target_features.get(kind, {})) & set(candidate_features.get(kind, {}))
                for value in sorted(shared)[:8]:
                    matches.append({
                        "feature": kind,
                        "basis": basis,
                        "value": _safe_basis_value(kind, value),
                        "weight": weight,
                        "source_event_ids": sorted(target_features[kind][value])[:32],
                        "related_event_ids": sorted(candidate_features[kind][value])[:32],
                    })

            if not matches:
                continue
            matches.sort(key=lambda item: (-float(item["weight"]), item["feature"], item["value"]))
            score = self._score(matches)
            if score < bounded_min_score:
                continue
            timestamps = [str(row["timestamp"]) for row in rows]
            correlations.append({
                "session_id": candidate_session_id,
                "method": "evidence_overlap_v1",
                "score": score,
                "strength": self._strength(score),
                "evidence_basis": matches[:32],
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "event_count": len(rows),
                "source_ips": sorted({str(row["source_ip"]) for row in rows if row["source_ip"]})[:64],
                "honeypots": sorted({str(row["honeypot"]) for row in rows if row["honeypot"]})[:64],
                "services": sorted({str(row["service"]) for row in rows if row["service"]})[:64],
                "attribution": False,
            })

        correlations.sort(key=lambda item: (item["score"], item["last_seen"], item["session_id"]), reverse=True)
        return {
            "schema_version": CORRELATION_SCHEMA_VERSION,
            "session_id": clean_session_id,
            "items": correlations[:bounded_limit],
            "analysis": {
                "method": "evidence_overlap_v1",
                "window_hours": bounded_hours,
                "candidate_event_limit": self.max_events,
                "candidate_events_truncated": truncated,
                "min_score": bounded_min_score,
                "score_semantics": "deterministic evidence-overlap strength, not attribution probability",
                "attribution_inferred": False,
            },
        }
