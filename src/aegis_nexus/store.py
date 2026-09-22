from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .correlation import session_id_for, session_identity, should_join


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, honeypot TEXT NOT NULL,
                    service TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'unknown',
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL, last_seen TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, honeypot TEXT NOT NULL,
                    event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT,
                    session_id TEXT NOT NULL, protocol TEXT, service TEXT, destination_port INTEGER,
                    country TEXT, asn TEXT, latitude REAL, longitude REAL,
                    observed TEXT NOT NULL, enrichment TEXT NOT NULL, derived TEXT NOT NULL,
                    hypotheses TEXT NOT NULL, schema_version TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, timestamp ASC);
            """)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)")}
            if "protocol" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT NOT NULL DEFAULT 'unknown'")
            if "destination_port" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN destination_port INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_lookup_v2 "
                "ON sessions(source_ip, honeypot, service, protocol, destination_port, last_seen)"
            )

    def _select_or_create_session(self, conn: sqlite3.Connection, event: dict[str, Any]) -> str:
        source_ip, honeypot, service, protocol, destination_port = session_identity(event)
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
        identity = (source_ip, honeypot, service, protocol, destination_port)
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

    def ingest(self, event: dict[str, Any]) -> dict[str, Any]:
        observed = event["observed"]
        country, asn, latitude, longitude = self._geo(event["enrichment"])
        with self.connect() as conn:
            session_id = self._select_or_create_session(conn, event)
            conn.execute("""
                INSERT INTO events(
                    id,timestamp,honeypot,event_type,severity,source_ip,session_id,protocol,service,
                    destination_port,country,asn,latitude,longitude,observed,enrichment,derived,hypotheses,schema_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event["id"], event["timestamp"], event["honeypot"], event["event_type"], event["severity"],
                observed.get("source_ip"), session_id, observed.get("protocol"), observed.get("service"),
                observed.get("destination_port"), country, asn, latitude, longitude,
                json.dumps(event["observed"], ensure_ascii=False),
                json.dumps(event["enrichment"], ensure_ascii=False),
                json.dumps(event["derived"], ensure_ascii=False),
                json.dumps(event["hypotheses"], ensure_ascii=False), event["schema_version"],
            ))
        return {**event, "session_id": session_id}

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for field in ("observed", "enrichment", "derived", "hypotheses"):
            data[field] = json.loads(data[field])
        return data

    def prune(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            deleted = cur.rowcount
            conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events)")
        return deleted

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return self._decode(row) if row else None

    def list_events(self, limit: int = 100, q: str | None = None, filters: dict[str, str] | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        allowed = {"country", "protocol", "service", "honeypot", "severity", "source_ip", "session_id", "event_type"}
        for key, value in (filters or {}).items():
            if value and key in allowed:
                clauses.append(f"{key} = ?")
                params.append(value)
        if q:
            clauses.append("(source_ip LIKE ? OR event_type LIKE ? OR honeypot LIKE ? OR observed LIKE ? OR enrichment LIKE ? OR derived LIKE ?)")
            needle = f"%{q[:128]}%"
            params.extend([needle] * 6)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self.connect() as conn:
            rows = conn.execute(f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [self._decode(row) for row in rows]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not session:
                return None
            events = conn.execute("SELECT * FROM events WHERE session_id=? ORDER BY timestamp ASC", (session_id,)).fetchall()
        return {"session": dict(session), "events": [self._decode(row) for row in events]}

    def ip_profile(self, ip: str) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 500", (ip,)).fetchall()
        events = [self._decode(row) for row in rows]
        return {
            "source_ip": ip,
            "event_count": len(events),
            "sessions": sorted({e["session_id"] for e in events}),
            "countries": sorted({e["country"] for e in events if e.get("country")}),
            "asns": sorted({e["asn"] for e in events if e.get("asn")}),
            "services": sorted({e["service"] for e in events if e.get("service")}),
            "destination_ports": sorted({e["destination_port"] for e in events if e.get("destination_port")}),
            "events": events,
        }

    @staticmethod
    def _top(events: list[dict[str, Any]], field: str, n: int = 10) -> list[dict[str, Any]]:
        counts = Counter(str(e.get(field)) for e in events if e.get(field) not in (None, ""))
        return [{"label": label, "value": value} for label, value in counts.most_common(n)]

    @staticmethod
    def _matches_q(event: dict[str, Any], q: str | None) -> bool:
        if not q:
            return True
        needle = q[:128].casefold()
        searchable = (
            event.get("source_ip"),
            event.get("event_type"),
            event.get("honeypot"),
            event.get("protocol"),
            event.get("service"),
            event.get("country"),
            event.get("asn"),
            json.dumps(event.get("observed", {}), ensure_ascii=False),
            json.dumps(event.get("enrichment", {}), ensure_ascii=False),
            json.dumps(event.get("derived", {}), ensure_ascii=False),
        )
        return any(needle in str(value).casefold() for value in searchable if value not in (None, ""))

    def dashboard(self, hours: int = 24, include_simulation: bool = False, q: str | None = None) -> dict[str, Any]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC", (since,)).fetchall()
        events = [self._decode(row) for row in rows]
        if not include_simulation:
            events = [e for e in events if e["derived"].get("data_mode") != "simulation"]
        events = [e for e in events if self._matches_q(e, q)]
        timeline: dict[str, int] = defaultdict(int)
        heatmap = [[0 for _ in range(24)] for _ in range(7)]
        credentials, commands, mitre, ids = Counter(), Counter(), Counter(), Counter()
        for e in events:
            ts = datetime.fromisoformat(e["timestamp"])
            timeline[ts.strftime("%Y-%m-%dT%H:00Z")] += 1
            heatmap[ts.weekday()][ts.hour] += 1
            cred = e["observed"].get("credential")
            if isinstance(cred, dict) and cred.get("username"):
                credentials[str(cred["username"])] += 1
            if e["observed"].get("command"):
                commands[str(e["observed"]["command"])[:120]] += 1
            for item in e["derived"].get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            if e["event_type"] == "ids.alert":
                alert = e["observed"].get("alert") if isinstance(e["observed"].get("alert"), dict) else {}
                signature = e["observed"].get("signature") or alert.get("signature")
                if signature:
                    ids[str(signature)[:160]] += 1
        return {
            "window_hours": bounded_hours,
            "query": q or "",
            "totals": {
                "events": len(events),
                "unique_source_ip": len({e["source_ip"] for e in events if e.get("source_ip")}),
                "sessions": len({e["session_id"] for e in events}),
                "critical": sum(1 for e in events if e["severity"] == "critical"),
            },
            "timeline": [{"label": k, "value": timeline[k]} for k in sorted(timeline)],
            "heatmap": heatmap,
            "country": self._top(events, "country"),
            "asn": self._top(events, "asn"),
            "destination_port": self._top(events, "destination_port"),
            "protocol": self._top(events, "protocol"),
            "service": self._top(events, "service"),
            "honeypot": self._top(events, "honeypot"),
            "credentials": [{"label": k, "value": v} for k, v in credentials.most_common(10)],
            "commands": [{"label": k, "value": v} for k, v in commands.most_common(10)],
            "ids_alerts": [{"label": k, "value": v} for k, v in ids.most_common(10)],
            "mitre": [{"label": k, "value": v} for k, v in mitre.most_common(10)],
            "map_points": [
                {"lat": e["latitude"], "lon": e["longitude"], "source_ip": e["source_ip"], "country": e["country"]}
                for e in events if e.get("latitude") is not None and e.get("longitude") is not None
            ][-250:],
        }

    def report(self, session_id: str) -> dict[str, Any] | None:
        bundle = self.get_session(session_id)
        if not bundle:
            return None
        events = bundle["events"]
        credentials, commands, payloads, iocs, mappings, enrichments = [], [], [], [], [], []
        for e in events:
            cred = e["observed"].get("credential")
            if isinstance(cred, dict):
                credentials.append({
                    "event_id": e["id"],
                    "username": cred.get("username"),
                    "password": cred.get("password"),
                    "password_sha256": cred.get("password_sha256"),
                })
            if e["observed"].get("command"):
                commands.append({"event_id": e["id"], "command": e["observed"]["command"]})
            if e["observed"].get("payload"):
                payloads.append({"event_id": e["id"], "payload": e["observed"]["payload"]})
            if e["enrichment"]:
                enrichments.append({"event_id": e["id"], "sources": e["enrichment"]})
            for ioc in e["derived"].get("ioc", []) or []:
                iocs.append({"event_id": e["id"], "ioc": ioc})
            for family in ("mitre", "cve"):
                for item in e["derived"].get(family, []) or []:
                    mappings.append({"event_id": e["id"], "family": family, "mapping": item})
        return {
            "report_type": "investigation_session",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session": bundle["session"],
            "facts": {
                "event_count": len(events),
                "event_types": sorted({e["event_type"] for e in events}),
                "source_ips": sorted({e["source_ip"] for e in events if e.get("source_ip")}),
                "services": sorted({e["service"] for e in events if e.get("service")}),
                "destination_ports": sorted({e["destination_port"] for e in events if e.get("destination_port")}),
            },
            "credentials": credentials,
            "commands": commands,
            "payloads": payloads,
            "enrichment": enrichments,
            "derived_iocs": iocs,
            "evidence_backed_mappings": mappings,
            "events": events,
            "limitations": [
                "IP, ASN and geolocation do not establish human identity or attribution.",
                "External enrichment is contextual and may be stale or inaccurate.",
                "Derived MITRE/CVE entries are included only when rationale and evidence were stored with the event.",
            ],
        }

    def relations(self, session_id: str) -> dict[str, Any]:
        bundle = self.get_session(session_id)
        if not bundle:
            return {"nodes": [], "edges": []}
        nodes: dict[str, dict[str, Any]] = {}
        edges: set[tuple[str, str, str]] = set()

        def add(kind: str, value: Any) -> str | None:
            if value in (None, ""):
                return None
            label = str(value)
            digest = hashlib.sha256(f"{kind}\0{label}".encode("utf-8", "replace")).hexdigest()[:20]
            node_id = f"{kind}:{digest}"
            nodes[node_id] = {"id": node_id, "kind": kind, "label": label[:180]}
            return node_id

        for e in bundle["events"]:
            event_node = add("event", e["id"])
            session_node = add("session", e["session_id"])
            ip_node = add("ip", e.get("source_ip"))
            asn_node = add("asn", e.get("asn"))
            port_node = add("port", e.get("destination_port"))
            service_node = add("service", e.get("service"))
            cred = e["observed"].get("credential") if isinstance(e["observed"].get("credential"), dict) else {}
            user_node = add("credential", cred.get("username"))
            payload_node = add("payload", e["observed"].get("payload") or e["observed"].get("command"))
            for target, relation in [
                (session_node, "belongs_to"),
                (ip_node, "source"),
                (asn_node, "enriched_asn"),
                (port_node, "targets_port"),
                (service_node, "targets_service"),
                (user_node, "uses_username"),
                (payload_node, "observed_payload"),
            ]:
                if event_node and target:
                    edges.add((event_node, target, relation))
            for item in e["derived"].get("mitre", []) or []:
                mitre_node = add("mitre", item.get("technique_id") if isinstance(item, dict) else None)
                if event_node and mitre_node:
                    edges.add((event_node, mitre_node, "mapped_with_evidence"))
            for ioc in e["derived"].get("ioc", []) or []:
                ioc_node = add("ioc", ioc.get("value") if isinstance(ioc, dict) else ioc)
                if event_node and ioc_node:
                    edges.add((event_node, ioc_node, "derived_ioc"))
        return {
            "nodes": list(nodes.values()),
            "edges": [{"source": a, "target": b, "relation": r} for a, b, r in sorted(edges)],
        }
