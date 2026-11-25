from __future__ import annotations

import json
import shutil
import sqlite3
import time
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .event_chain import HASHED_COLUMNS, append_record, verify_chain
from .correlation import explicit_session_token, session_id_for, session_id_for_explicit, session_identity, should_join
from .migrations import LATEST_SCHEMA_VERSION, applied_migrations, apply_migrations, enable_wal, schema_version
from .sensor_sequence import SEQUENCE_FIELD, record_event_sequence, record_heartbeat_sequence, sequence_summary
from .store_relations import build_relation_graph
from .store_cases import CaseStoreMixin
from .store_analytics import AnalyticsStoreMixin
from .store_events import EventStoreMixin
from .store_sessions import SessionStoreMixin


# Fixed vocabulary of collector-side operational counters (never attacker-set).
COLLECTOR_COUNTERS = (
    "sensor_auth_failures",
    "sensor_replay_rejections",
    "ingest_validation_rejections",
    "load_shed_events",
)


class Store(EventStoreMixin, SessionStoreMixin, AnalyticsStoreMixin, CaseStoreMixin):
    def __init__(
        self,
        path: str,
        retention_days: int = 30,
        max_events: int = 500_000,
        analytics_max_events: int = 20_000,
        session_max_events: int = 5_000,
        relation_max_nodes: int = 160,
        max_cases: int = 10_000,
        case_retention_days: int = 0,
        migration_backup_dir: str | None = None,
        migration_backup_keep: int = 14,
    ):
        self.path = path
        # Optional resolver for derived IOC evidence (injected by the app so the
        # Store never imports the IOC workspace). Signature: (ioc_id) -> dict|None.
        self._ioc_resolver: Callable[[str], dict[str, Any] | None] | None = None
        self.retention_days = max(0, retention_days)
        self.max_events = max(1_000, max_events)
        self.analytics_max_events = max(100, min(analytics_max_events, self.max_events))
        self.session_max_events = max(100, min(int(session_max_events), self.max_events))
        self.relation_max_nodes = max(32, min(int(relation_max_nodes), 1_000))
        self.max_cases = max(1, min(int(max_cases), 1_000_000))
        self.case_retention_days = max(0, min(int(case_retention_days), 3650))
        self.migration_backup_dir = migration_backup_dir
        self.migration_backup_keep = max(1, min(int(migration_backup_keep), 365))
        self._ingest_since_maintenance = 0
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()
        self.maintain(force=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        enable_wal(conn)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            apply_migrations(
                conn,
                backup_dir=self.migration_backup_dir,
                backup_keep=self.migration_backup_keep,
            )

    def reserve_sensor_nonce(
        self,
        sensor_id: str,
        nonce: str,
        *,
        window_seconds: int,
        max_nonces_per_sensor: int,
    ) -> bool:
        """Atomically reserve a signed-request nonce across collector workers."""
        now = int(time.time())
        expires_at = now + max(1, min(int(window_seconds), 3600))
        capacity = max(1, min(int(max_nonces_per_sensor), 100_000))
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM sensor_replay_nonces WHERE expires_at<=?", (now,))
            count = conn.execute(
                "SELECT COUNT(*) FROM sensor_replay_nonces WHERE sensor_id=?",
                (sensor_id,),
            ).fetchone()[0]
            if count >= capacity:
                return False
            cursor = conn.execute(
                "INSERT OR IGNORE INTO sensor_replay_nonces(sensor_id,nonce,expires_at) VALUES(?,?,?)",
                (sensor_id, nonce, expires_at),
            )
            return cursor.rowcount == 1

    def _select_or_create_session(self, conn: sqlite3.Connection, event: dict[str, Any]) -> str:
        source_ip, honeypot, service, protocol, destination_port = session_identity(event)
        identity = (source_ip, honeypot, service, protocol, destination_port)
        explicit = explicit_session_token(event)

        if explicit:
            session_id = session_id_for_explicit(identity, explicit)
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE sessions
                    SET started_at=CASE WHEN started_at > ? THEN ? ELSE started_at END,
                        last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                        event_count=event_count+1
                    WHERE id=?
                    """,
                    (
                        event["timestamp"], event["timestamp"],
                        event["timestamp"], event["timestamp"],
                        session_id,
                    ),
                )
                return session_id
            conn.execute(
                """
                INSERT INTO sessions(
                    id,source_ip,honeypot,service,protocol,destination_port,started_at,last_seen,event_count
                ) VALUES(?,?,?,?,?,?,?,?,1)
                """,
                (
                    session_id, source_ip, honeypot, service, protocol, destination_port,
                    event["timestamp"], event["timestamp"],
                ),
            )
            return session_id

        row = conn.execute(
            """
            SELECT * FROM sessions
            WHERE source_ip=? AND honeypot=? AND service=? AND protocol=? AND destination_port=?
            ORDER BY last_seen DESC LIMIT 1
            """,
            (source_ip, honeypot, service, protocol, destination_port),
        ).fetchone()
        if row and should_join(row["last_seen"], event["timestamp"]):
            conn.execute(
                "UPDATE sessions SET last_seen=?, event_count=event_count+1 WHERE id=?",
                (event["timestamp"], row["id"]),
            )
            return row["id"]

        session_id = session_id_for(identity, event["timestamp"])
        conn.execute(
            """
            INSERT INTO sessions(
                id,source_ip,honeypot,service,protocol,destination_port,started_at,last_seen,event_count
            ) VALUES(?,?,?,?,?,?,?,?,1)
            """,
            (session_id, source_ip, honeypot, service, protocol, destination_port, event["timestamp"], event["timestamp"]),
        )
        return session_id

    @staticmethod
    def _geo(enrichment: dict[str, Any]) -> tuple[str | None, str | None, float | None, float | None]:
        geo = enrichment.get("geo") if isinstance(enrichment.get("geo"), dict) else {}
        asn = enrichment.get("asn") if isinstance(enrichment.get("asn"), dict) else {}
        data = geo.get("data") if isinstance(geo.get("data"), dict) else {}
        asn_data = asn.get("data") if isinstance(asn.get("data"), dict) else {}
        return data.get("country"), asn_data.get("asn"), data.get("latitude"), data.get("longitude")

    def ingest(self, event: dict[str, Any], collector_received_at: str | None = None) -> dict[str, Any]:
        observed = event["observed"]
        received_at = collector_received_at or datetime.now(timezone.utc).isoformat()
        country, asn, latitude, longitude = self._geo(event["enrichment"])
        with self.connect() as conn:
            # Write lock first: the hash chain head must be read and advanced atomically.
            conn.execute("BEGIN IMMEDIATE")
            session_id = self._select_or_create_session(conn, event)
            conn.execute("""
                INSERT INTO events(
                    id,timestamp,received_at,honeypot,event_type,severity,source_ip,session_id,protocol,service,
                    destination_port,country,asn,latitude,longitude,observed,enrichment,derived,hypotheses,collector,schema_version,
                    collector_received_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event["id"], event["timestamp"], received_at, event["honeypot"], event["event_type"], event["severity"],
                observed.get("source_ip"), session_id, observed.get("protocol"), observed.get("service"),
                observed.get("destination_port"), country, asn, latitude, longitude,
                json.dumps(event["observed"], ensure_ascii=False),
                json.dumps(event["enrichment"], ensure_ascii=False),
                json.dumps(event["derived"], ensure_ascii=False),
                json.dumps(event["hypotheses"], ensure_ascii=False),
                json.dumps(event.get("collector", {}), ensure_ascii=False),
                event["schema_version"], received_at,
            ))
            stored = conn.execute(
                f"SELECT {', '.join(HASHED_COLUMNS)} FROM events WHERE id=?", (event["id"],)
            ).fetchone()
            append_record(conn, dict(zip(HASHED_COLUMNS, tuple(stored), strict=False)))
            sequence = observed.get(SEQUENCE_FIELD)
            if isinstance(sequence, dict):
                # Same transaction as the event row: a sequence counts as received
                # only if the event it numbers was actually stored.
                record_event_sequence(conn, event["honeypot"], sequence, received_at)
        self._ingest_since_maintenance += 1
        self.maintain()
        safe_event = self._export_safe_event(event)
        return {
            **safe_event,
            "session_id": session_id,
            "received_at": received_at,
            "collector_received_at": received_at,
        }

    def verify_event_chain(self) -> dict[str, Any]:
        """Verify the tamper-evident event hash chain (read-only)."""
        with self.connect() as conn:
            return verify_chain(conn)

    def maintain(self, force: bool = False) -> dict[str, int]:
        if not force and self._ingest_since_maintenance < 100:
            return {"retention_deleted": 0, "capacity_deleted": 0, "case_retention_deleted": 0}
        self._ingest_since_maintenance = 0
        retention_deleted = self.prune(self.retention_days)
        case_retention_deleted = self.prune_cases(self.case_retention_days)
        capacity_deleted = 0
        with self.connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
            overflow = max(0, int(count) - self.max_events)
            if overflow:
                cur = conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY collector_received_at ASC, id ASC LIMIT ?)",
                    (overflow,),
                )
                capacity_deleted = cur.rowcount
                conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")
        with self.connect() as checkpoint_conn:
            checkpoint_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {
            "retention_deleted": retention_deleted,
            "capacity_deleted": capacity_deleted,
            "case_retention_deleted": case_retention_deleted,
        }

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for field in ("observed", "enrichment", "derived", "hypotheses", "collector"):
            raw = data.get(field)
            data[field] = json.loads(raw) if isinstance(raw, str) and raw else {}
        observed = data.get("observed")
        if isinstance(observed, dict):
            credential = observed.get("credential")
            if isinstance(credential, dict):
                # Cleartext credential storage is an explicit database-retention choice only.
                # Operator APIs/UI always receive the deterministic fingerprint and length,
                # never the collected secret itself.
                credential.pop("password", None)
        return data

    def prune(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM events WHERE collector_received_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")
        return deleted

    def prune_cases(self, retention_days: int | None = None) -> int:
        days = self.case_retention_days if retention_days is None else max(0, int(retention_days))
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute(
                """
                DELETE FROM cases
                WHERE status='closed' AND closed_at IS NOT NULL AND closed_at < ?
                """,
                (cutoff,),
            )
            return cur.rowcount

    @staticmethod
    def _extract_external_enrichment(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for event in events:
            enrichment = event.get("enrichment") or {}
            for kind, value in enrichment.items():
                if not isinstance(value, dict):
                    continue
                source = value.get("source")
                observed_at = value.get("observed_at")
                data = value.get("data")
                if not source or not observed_at:
                    continue
                fingerprint = json.dumps(
                    {"kind": kind, "source": source, "data": data},
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                entries.append({
                    "kind": kind,
                    "source": source,
                    "observed_at": observed_at,
                    "data": data,
                    "event_id": event["id"],
                    "provenance": "external_enrichment",
                    "classification": "threat_intelligence" if kind == "threat_context" else "context_enrichment",
                })
        entries.sort(key=lambda item: str(item.get("observed_at") or ""), reverse=True)
        return entries[:100]

    @staticmethod
    def _counter_items(counter: Counter, limit: int = 10) -> list[dict[str, Any]]:
        return [{"label": str(label), "value": int(value)} for label, value in counter.most_common(limit)]

    @staticmethod
    def _credential_secret_summary(credential: dict[str, Any]) -> dict[str, Any] | None:
        complete = credential.get("password_complete") is not False
        if not complete and credential.get("sensor_reported_password_sha256"):
            digest = str(credential["sensor_reported_password_sha256"])
            length = credential.get("sensor_reported_password_length")
            return {
                "label": f"sensor-sha256:{digest[:16]} · len:{length if length is not None else '?'} · truncated",
                "sha256": digest,
                "length": length,
                "complete": False,
                "provenance": "sensor_reported_original",
            }
        digest = credential.get("password_sha256")
        if not digest:
            return None
        length = credential.get("password_length")
        return {
            "label": f"sha256:{str(digest)[:16]} · len:{length if length is not None else '?'}",
            "sha256": str(digest),
            "length": length,
            "complete": complete,
            "provenance": "collector_received_value",
        }

    def ip_profile(self, ip: str) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 500",
                (ip,),
            ).fetchall()
        events = [self._decode(row) for row in rows]
        first_seen = min((event["timestamp"] for event in events), default=None)
        last_seen = max((event["timestamp"] for event in events), default=None)
        severities = Counter(event["severity"] for event in events)
        event_types = Counter(event["event_type"] for event in events)
        honeypots = Counter(event["honeypot"] for event in events)
        usernames: Counter[str] = Counter()
        credential_secrets: Counter[str] = Counter()
        commands: Counter[str] = Counter()
        payloads: Counter[str] = Counter()
        ids_alerts: Counter[str] = Counter()
        mitre: Counter[str] = Counter()
        cves: Counter[str] = Counter()
        iocs: Counter[str] = Counter()

        for event in events:
            observed = event.get("observed") or {}
            derived = event.get("derived") or {}
            credential = observed.get("credential")
            if isinstance(credential, dict):
                if credential.get("username"):
                    usernames[str(credential["username"])[:160]] += 1
                secret = self._credential_secret_summary(credential)
                if secret:
                    credential_secrets[secret["label"]] += 1
            if observed.get("command"):
                commands[str(observed["command"])[:160]] += 1
            if observed.get("payload"):
                payloads[str(observed["payload"])[:160]] += 1
            if event.get("event_type") == "ids.alert":
                alert = observed.get("alert") if isinstance(observed.get("alert"), dict) else {}
                signature = observed.get("signature") or alert.get("signature")
                if signature:
                    ids_alerts[str(signature)[:180]] += 1
            for item in derived.get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            for item in derived.get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves[str(item["cve_id"])] += 1
            for item in derived.get("ioc", []) or []:
                if isinstance(item, dict) and item.get("type") and item.get("value") not in (None, ""):
                    iocs[f"{item['type']}: {str(item['value'])[:160]}"] += 1

        external_enrichment = self._extract_external_enrichment(events)
        threat_intelligence = [
            item for item in external_enrichment
            if item.get("classification") == "threat_intelligence"
        ]
        return {
            "source_ip": ip,
            "event_count": len(events),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "sessions": sorted({event["session_id"] for event in events}),
            "countries": sorted({event["country"] for event in events if event.get("country")}),
            "asns": sorted({event["asn"] for event in events if event.get("asn")}),
            "services": sorted({event["service"] for event in events if event.get("service")}),
            "protocols": sorted({event["protocol"] for event in events if event.get("protocol")}),
            "destination_ports": sorted({event["destination_port"] for event in events if event.get("destination_port")}),
            "severity": dict(severities),
            "activity": {
                "event_types": self._counter_items(event_types),
                "honeypots": self._counter_items(honeypots),
                "usernames": self._counter_items(usernames),
                "credential_secret_fingerprints": self._counter_items(credential_secrets),
                "commands": self._counter_items(commands),
                "payloads": self._counter_items(payloads),
                "ids_alerts": self._counter_items(ids_alerts),
                "mitre": self._counter_items(mitre),
                "cves": self._counter_items(cves),
                "iocs": self._counter_items(iocs),
            },
            "external_enrichment": external_enrichment,
            "threat_intelligence": threat_intelligence,
            "events": events,
            "attribution_limit": (
                "IP, ASN, geolocation and reputation enrichment describe infrastructure context; "
                "they do not identify the human operator or prove attribution."
            ),
        }

    def threat_intelligence(self, ip: str) -> dict[str, Any]:
        profile = self.ip_profile(ip)
        return {
            "source_ip": ip,
            "items": profile["external_enrichment"],
            "threat_intelligence_items": profile["threat_intelligence"],
            "context_enrichment_items": [
                item for item in profile["external_enrichment"]
                if item.get("classification") != "threat_intelligence"
            ],
            "limitations": [
                "External enrichment may be stale, incomplete or inaccurate.",
                "VPNs, proxies, NAT, hosting providers and compromised systems can obscure origin.",
                "GeoIP/ASN context is enrichment, not threat intelligence by itself.",
                "No threat actor or campaign attribution is inferred by AEGIS-NEXUS.",
            ],
        }

    def operational_health(self, min_free_bytes: int = 67_108_864) -> dict[str, Any]:
        threshold = max(0, int(min_free_bytes))
        database_ready = False
        database_schema_version: int | None = None
        database_migrations: list[dict[str, Any]] = []
        try:
            with self.connect() as conn:
                conn.execute("SELECT 1").fetchone()
                database_schema_version = schema_version(conn)
                database_migrations = applied_migrations(conn)
            database_ready = True
        except sqlite3.Error:
            database_ready = False
        schema_current = database_schema_version == LATEST_SCHEMA_VERSION

        storage_free_bytes: int | None = None
        try:
            storage_free_bytes = int(shutil.disk_usage(Path(self.path).parent).free)
        except OSError:
            storage_free_bytes = None
        storage_ready = storage_free_bytes is not None and storage_free_bytes >= threshold

        # On-disk footprint: main DB plus WAL/SHM sidecars when present.
        database_size_bytes = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                database_size_bytes += Path(self.path + suffix).stat().st_size
            except OSError:
                pass

        event_count: int | None = None
        if database_ready:
            try:
                with self.connect() as conn:
                    event_count = int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            except sqlite3.Error:
                event_count = None

        capacity_used = (
            event_count / self.max_events if event_count is not None and self.max_events else None
        )
        # Deterministic platform state. Critical: cannot operate safely.
        # Degraded: operational but a bound is close. Healthy: otherwise.
        if not (database_ready and schema_current and storage_ready):
            state = "critical"
        elif (
            (storage_free_bytes is not None and storage_free_bytes < threshold * 2)
            or (capacity_used is not None and capacity_used >= 0.9)
        ):
            state = "degraded"
        else:
            state = "healthy"

        return {
            "ready": database_ready and schema_current and storage_ready,
            "state": state,
            "database_ready": database_ready,
            "database_schema": {
                "version": database_schema_version,
                "latest_supported": LATEST_SCHEMA_VERSION,
                "current": schema_current,
                "migrations": database_migrations,
            },
            "storage_ready": storage_ready,
            "storage_free_bytes": storage_free_bytes,
            "min_free_bytes": threshold,
            "storage": {
                "database_size_bytes": database_size_bytes,
                "event_count": event_count,
                "max_events": self.max_events,
                "capacity_used_fraction": round(capacity_used, 4) if capacity_used is not None else None,
                "retention_days": self.retention_days,
            },
        }

    def record_sensor_heartbeat(
        self,
        sensor_id: str,
        sensor_timestamp: str | None = None,
        collector_received_at: str | None = None,
        event_sequence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        bounded_sensor_id = str(sensor_id)[:96]
        if not bounded_sensor_id:
            raise ValueError("sensor_id is required")
        received_at = collector_received_at or datetime.now(timezone.utc).isoformat()
        bounded_timestamp = str(sensor_timestamp)[:64] if sensor_timestamp else None
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO sensor_heartbeats(sensor_id,sensor_timestamp,collector_received_at,status)
                VALUES(?,?,?,'healthy')
                ON CONFLICT(sensor_id) DO UPDATE SET
                    sensor_timestamp=excluded.sensor_timestamp,
                    collector_received_at=excluded.collector_received_at,
                    status='healthy'
                """,
                (bounded_sensor_id, bounded_timestamp, received_at),
            )
            if event_sequence is not None:
                record_heartbeat_sequence(conn, bounded_sensor_id, event_sequence, received_at)
        return {
            "sensor_id": bounded_sensor_id,
            "sensor_timestamp": bounded_timestamp,
            "collector_received_at": received_at,
            "status": "healthy",
        }

    def sensor_telemetry_observation(
        self,
        configured_sensor_ids: list[str] | tuple[str, ...] | set[str] | None = None,
        recent_hours: int = 24,
        heartbeat_stale_seconds: int = 180,
    ) -> dict[str, Any]:
        bounded_hours = max(1, min(int(recent_hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    honeypot,
                    MAX(collector_received_at) AS last_received_at,
                    MAX(timestamp) AS latest_event_timestamp,
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN collector_received_at >= ? THEN 1 ELSE 0 END) AS recent_events
                FROM events
                GROUP BY honeypot
                ORDER BY honeypot COLLATE NOCASE
                """,
                (since,),
            ).fetchall()

        observed = {
            str(row["honeypot"]): {
                "sensor_id": str(row["honeypot"]),
                "configured": False,
                "last_received_at": row["last_received_at"],
                "latest_event_timestamp": row["latest_event_timestamp"],
                "total_events": int(row["total_events"] or 0),
                "recent_events": int(row["recent_events"] or 0),
                "last_heartbeat_at": None,
                "sensor_heartbeat_timestamp": None,
                "heartbeat_state": "never",
            }
            for row in rows
        }
        with self.connect() as conn:
            heartbeat_rows = conn.execute(
                """
                SELECT sensor_id,sensor_timestamp,collector_received_at,status
                FROM sensor_heartbeats
                ORDER BY sensor_id COLLATE NOCASE
                """
            ).fetchall()
        now = datetime.now(timezone.utc)
        stale_after = max(30, min(int(heartbeat_stale_seconds), 86400))
        for row in heartbeat_rows:
            sensor_id = str(row["sensor_id"])
            item = observed.setdefault(
                sensor_id,
                {
                    "sensor_id": sensor_id,
                    "configured": False,
                    "last_received_at": None,
                    "latest_event_timestamp": None,
                    "total_events": 0,
                    "recent_events": 0,
                    "last_heartbeat_at": None,
                    "sensor_heartbeat_timestamp": None,
                    "heartbeat_state": "never",
                },
            )
            received = str(row["collector_received_at"])
            try:
                received_dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                age_seconds = max(0, int((now - received_dt.astimezone(timezone.utc)).total_seconds()))
            except (TypeError, ValueError):
                age_seconds = stale_after + 1
            item["last_heartbeat_at"] = received
            item["sensor_heartbeat_timestamp"] = row["sensor_timestamp"]
            item["heartbeat_age_seconds"] = age_seconds
            item["heartbeat_state"] = "healthy" if age_seconds <= stale_after else "stale"
        configured = {
            str(sensor_id)[:96]
            for sensor_id in (configured_sensor_ids or [])
            if str(sensor_id)
        }
        for sensor_id in configured:
            item = observed.setdefault(
                sensor_id,
                {
                    "sensor_id": sensor_id,
                    "configured": True,
                    "last_received_at": None,
                    "latest_event_timestamp": None,
                    "total_events": 0,
                    "recent_events": 0,
                    "last_heartbeat_at": None,
                    "sensor_heartbeat_timestamp": None,
                    "heartbeat_state": "never",
                },
            )
            item["configured"] = True

        with self.connect() as conn:
            sequences = sequence_summary(conn)
        for sensor_id in sequences:
            observed.setdefault(
                sensor_id,
                {
                    "sensor_id": sensor_id,
                    "configured": False,
                    "last_received_at": None,
                    "latest_event_timestamp": None,
                    "total_events": 0,
                    "recent_events": 0,
                    "last_heartbeat_at": None,
                    "sensor_heartbeat_timestamp": None,
                    "heartbeat_state": "never",
                },
            )
        for sensor_id, item in observed.items():
            item["event_sequence"] = sequences.get(sensor_id) or {"state": "unsequenced"}

        items = [observed[key] for key in sorted(observed, key=str.casefold)]
        return {
            "recent_hours": bounded_hours,
            "configured_sensors": len(configured),
            "configured_with_recent_telemetry": sum(
                1 for item in items if item["configured"] and item["recent_events"] > 0
            ),
            "configured_with_healthy_heartbeat": sum(
                1 for item in items if item["configured"] and item["heartbeat_state"] == "healthy"
            ),
            "heartbeat_stale_seconds": stale_after,
            "sensors_with_sequence_gaps": sum(
                1 for item in items if item["event_sequence"]["state"] == "gaps_detected"
            ),
            "missing_sequenced_events": sum(int(item["event_sequence"].get("missing", 0)) for item in items),
            "observed_sensor_ids": len(items),
            "items": items,
            "interpretation": (
                "Heartbeat state uses collector receipt time. 'healthy' confirms recent authenticated "
                "sensor contact; 'stale' means contact is overdue and does not by itself identify the cause. "
                "Ordinary event telemetry receipt alone is not proof that a sensor is online or offline. "
                "Sequence gaps count events a sensor numbered but the collector never stored (evidence loss); "
                "a just-emitted event can appear missing until it arrives, and 'unsequenced' sources such as "
                "Suricata forwarding carry no sequence."
            ),
        }

    def sensor_health(
        self,
        configured_sensor_ids: list[str] | tuple[str, ...] | set[str] | None = None,
        recent_hours: int = 24,
        heartbeat_stale_seconds: int = 180,
    ) -> dict[str, Any]:
        """Per-sensor health derived from telemetry receipt, heartbeats and gaps.

        A configured sensor with no recent telemetry and a stale/absent
        heartbeat is `silent` (the silence alert). Sequence gaps or a stale
        heartbeat with recent events are `degraded`; otherwise `healthy`. All
        signals come from already-stored data — nothing is inferred.
        """
        observation = self.sensor_telemetry_observation(
            configured_sensor_ids=configured_sensor_ids,
            recent_hours=recent_hours,
            heartbeat_stale_seconds=heartbeat_stale_seconds,
        )
        hours = observation["recent_hours"]
        sensors: list[dict[str, Any]] = []
        silent: list[str] = []
        for item in observation["items"]:
            recent = int(item.get("recent_events") or 0)
            heartbeat = item.get("heartbeat_state")
            gaps = (item.get("event_sequence") or {}).get("state") == "gaps_detected"
            if item.get("configured") and recent == 0 and heartbeat in {"stale", "never"}:
                state = "silent"
            elif gaps or heartbeat == "stale":
                state = "degraded"
            else:
                state = "healthy"
            sensors.append({
                **item,
                "last_event_at": item.get("latest_event_timestamp"),
                "event_rate_per_hour": round(recent / hours, 3) if hours else 0.0,
                "sequence_gaps": gaps,
                "health": state,
            })
            if state == "silent":
                silent.append(str(item.get("sensor_id")))
        sensors.sort(key=lambda entry: str(entry.get("sensor_id")).casefold())
        return {
            "recent_hours": hours,
            "observation": observation,
            "sensors": sensors,
            "silent_sensors": silent,
            "silent_count": len(silent),
            "interpretation": (
                "A configured sensor is 'silent' when it has sent no telemetry in "
                "the window and its heartbeat is stale or absent — a high-signal "
                "alert, but not by itself proof of the cause (sensor down, network, "
                "or simply no attacker activity). Event rate and gaps are observed, "
                "never inferred."
            ),
        }

    def increment_counter(self, name: str, by: int = 1) -> None:
        """Atomically bump a collector operational counter (fixed vocabulary)."""
        if name not in COLLECTOR_COUNTERS:
            raise ValueError("unknown_counter")
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_counters(name, count, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    count = count + excluded.count,
                    updated_at = excluded.updated_at
                """,
                (name, max(0, int(by)), now),
            )

    def counters(self) -> dict[str, int]:
        result = {name: 0 for name in COLLECTOR_COUNTERS}
        try:
            with self.connect() as conn:
                rows = conn.execute("SELECT name, count FROM collector_counters").fetchall()
        except sqlite3.Error:
            return result
        for row in rows:
            key = str(row["name"])
            if key in result:
                result[key] = int(row["count"] or 0)
        return result

    @staticmethod
    def _export_safe_event(event: dict[str, Any]) -> dict[str, Any]:
        safe = deepcopy(event)
        observed = safe.get("observed")
        if isinstance(observed, dict):
            credential = observed.get("credential")
            if isinstance(credential, dict):
                credential.pop("password", None)
        return safe

    def report(self, session_id: str) -> dict[str, Any] | None:
        bundle = self.get_session(session_id)
        if not bundle:
            return None
        source_events = bundle["events"]
        events = [self._export_safe_event(event) for event in source_events]
        credentials, commands, payloads, iocs, mappings, enrichments = [], [], [], [], [], []
        for event in events:
            credential = event["observed"].get("credential")
            if isinstance(credential, dict):
                secret = self._credential_secret_summary(credential)
                credentials.append({
                    "event_id": event["id"],
                    "username": credential.get("username"),
                    "password_length": credential.get("password_length"),
                    "password_sha256": credential.get("password_sha256"),
                    "password_complete": credential.get("password_complete"),
                    "sensor_reported_password_length": credential.get("sensor_reported_password_length"),
                    "sensor_reported_password_sha256": credential.get("sensor_reported_password_sha256"),
                    "correlation_fingerprint": secret,
                })
            if event["observed"].get("command"):
                commands.append({"event_id": event["id"], "command": event["observed"]["command"]})
            if event["observed"].get("payload"):
                payloads.append({"event_id": event["id"], "payload": event["observed"]["payload"]})
            if event["enrichment"]:
                enrichments.append({"event_id": event["id"], "sources": event["enrichment"]})
            for ioc in event["derived"].get("ioc", []) or []:
                iocs.append({"event_id": event["id"], "ioc": ioc})
            for family in ("mitre", "cve"):
                for item in event["derived"].get(family, []) or []:
                    mappings.append({"event_id": event["id"], "family": family, "mapping": item})
        normalization_events = [
            event for event in events
            if isinstance((event.get("collector") or {}).get("normalization"), dict)
            and (event.get("collector") or {}).get("normalization", {}).get("lossy")
        ]
        truncated_normalization_events = [
            event for event in events
            if isinstance((event.get("collector") or {}).get("normalization"), dict)
            and (event.get("collector") or {}).get("normalization", {}).get("truncated")
        ]
        sensor_truncated_events = [
            event for event in events
            if isinstance((event.get("observed") or {}).get("sensor_capture"), dict)
            and (event.get("observed") or {}).get("sensor_capture", {}).get("truncated")
        ]
        sensor_rejected_events = [
            event for event in events
            if isinstance((event.get("observed") or {}).get("sensor_capture"), dict)
            and (event.get("observed") or {}).get("sensor_capture", {}).get("rejected")
        ]
        limitations = [
            "IP, ASN and geolocation do not establish human identity or attribution.",
            "External enrichment is contextual and may be stale or inaccurate.",
            "Derived MITRE/CVE entries are included only when rationale and evidence were stored with the event.",
            "Credential exports never include cleartext passwords, even when raw credential storage was explicitly enabled.",
            "collector_received_at is collector-controlled receipt metadata; event timestamp remains sensor-reported.",
            "Rows created before collector receipt tracking was introduced may have collector_received_at backfilled from the event timestamp.",
        ]
        if truncated_normalization_events:
            limitations.append(
                "One or more stored events contain explicitly disclosed field/collection truncation; inspect collector.normalization before treating payload text as complete."
            )
        if sensor_truncated_events:
            limitations.append(
                "One or more sensors captured only a bounded prefix of hostile input; inspect observed.sensor_capture before treating credentials, commands or payloads as complete."
            )
        if sensor_rejected_events:
            limitations.append(
                "One or more sensor inputs were rejected because a capture limit was exceeded; the rejection event proves the limit condition, not the full rejected content."
            )
        if bundle.get("analysis", {}).get("truncated"):
            limitations.append(
                "Session analysis was truncated to the configured latest-event limit; this report is not a complete retained-session timeline."
            )
        return {
            "report_type": "investigation_session",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analysis": bundle.get("analysis", {}),
            "session": bundle["session"],
            "summary": bundle["summary"],
            "facts": {
                "event_count": len(events),
                "events_with_lossy_normalization": len(normalization_events),
                "events_with_field_truncation": len(truncated_normalization_events),
                "events_with_sensor_truncation": len(sensor_truncated_events),
                "events_with_sensor_rejection": len(sensor_rejected_events),
                "event_types": sorted({event["event_type"] for event in events}),
                "source_ips": sorted({event["source_ip"] for event in events if event.get("source_ip")}),
                "services": sorted({event["service"] for event in events if event.get("service")}),
                "protocols": sorted({event["protocol"] for event in events if event.get("protocol")}),
                "destination_ports": sorted({
                    event["destination_port"] for event in events if event.get("destination_port")
                }),
                "sensor_first_timestamp": min((event["timestamp"] for event in events), default=None),
                "sensor_last_timestamp": max((event["timestamp"] for event in events), default=None),
                "collector_first_received": min(
                    (event["collector_received_at"] for event in events if event.get("collector_received_at")),
                    default=None,
                ),
                "collector_last_received": max(
                    (event["collector_received_at"] for event in events if event.get("collector_received_at")),
                    default=None,
                ),
            },
            "credentials": credentials,
            "commands": commands,
            "payloads": payloads,
            "enrichment": enrichments,
            "derived_iocs": iocs,
            "evidence_backed_mappings": mappings,
            "events": events,
            "limitations": limitations,
        }

    def relations(self, session_id: str) -> dict[str, Any]:
        bundle = self.get_session(session_id)
        if not bundle:
            return {"nodes": [], "edges": []}
        return build_relation_graph(
            bundle,
            max_nodes=self.relation_max_nodes,
            credential_secret_summary=self._credential_secret_summary,
        )
