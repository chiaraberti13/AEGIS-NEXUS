from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .correlation import session_id_for, session_identity, should_join


_EVENT_FILTERS = (
    "country",
    "protocol",
    "service",
    "honeypot",
    "severity",
    "source_ip",
    "session_id",
    "event_type",
)


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

    @staticmethod
    def _sql_filters(filters: dict[str, str] | None) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in (filters or {}).items():
            if value and key in _EVENT_FILTERS:
                clauses.append(f"{key} = ?")
                params.append(value[:256])
        return clauses, params

    def list_events(
        self,
        limit: int = 100,
        q: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses, params = self._sql_filters(filters)
        if q:
            clauses.append(
                "(source_ip LIKE ? OR event_type LIKE ? OR honeypot LIKE ? OR protocol LIKE ? OR "
                "service LIKE ? OR country LIKE ? OR asn LIKE ? OR observed LIKE ? OR enrichment LIKE ? OR derived LIKE ?)"
            )
            needle = f"%{q[:128]}%"
            params.extend([needle] * 10)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self.connect() as conn:
            rows = conn.execute(f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [self._decode(row) for row in rows]

    def list_sessions(self, limit: int = 100, q: str | None = None) -> list[dict[str, Any]]:
        params: list[Any] = []
        where = ""
        if q:
            needle = f"%{q[:128]}%"
            where = (
                " WHERE source_ip LIKE ? OR honeypot LIKE ? OR service LIKE ? OR protocol LIKE ? OR id LIKE ?"
            )
            params.extend([needle] * 5)
        params.append(max(1, min(limit, 300)))
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM sessions{where} ORDER BY last_seen DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _session_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
        credentials = 0
        commands = 0
        payloads = 0
        ids_alerts = 0
        mitre: set[str] = set()
        cves: set[str] = set()
        iocs = 0
        severity = Counter()
        event_types = Counter()
        for event in events:
            severity[event["severity"]] += 1
            event_types[event["event_type"]] += 1
            observed = event["observed"]
            derived = event["derived"]
            if isinstance(observed.get("credential"), dict):
                credentials += 1
            if observed.get("command"):
                commands += 1
            if observed.get("payload"):
                payloads += 1
            if event["event_type"] == "ids.alert":
                ids_alerts += 1
            for item in derived.get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre.add(str(item["technique_id"]))
            for item in derived.get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves.add(str(item["cve_id"]))
            iocs += len(derived.get("ioc", []) or [])
        return {
            "event_count": len(events),
            "severity": dict(severity),
            "event_types": [{"label": key, "value": value} for key, value in event_types.most_common()],
            "credentials": credentials,
            "commands": commands,
            "payloads": payloads,
            "ids_alerts": ids_alerts,
            "mitre": sorted(mitre),
            "cves": sorted(cves),
            "iocs": iocs,
        }

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not session:
                return None
            rows = conn.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY timestamp ASC",
                (session_id,),
            ).fetchall()
        events = [self._decode(row) for row in rows]
        return {
            "session": dict(session),
            "summary": self._session_summary(events),
            "events": events,
        }

    @staticmethod
    def _extract_threat_intelligence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
                })
        entries.sort(key=lambda item: str(item.get("observed_at") or ""), reverse=True)
        return entries[:100]

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
            "threat_intelligence": self._extract_threat_intelligence(events),
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
            "items": profile["threat_intelligence"],
            "limitations": [
                "External enrichment may be stale, incomplete or inaccurate.",
                "VPNs, proxies, NAT, hosting providers and compromised systems can obscure origin.",
                "No threat actor or campaign attribution is inferred by AEGIS-NEXUS.",
            ],
        }

    def filter_options(self, hours: int = 720) -> dict[str, list[str]]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        result: dict[str, list[str]] = {}
        columns = ("country", "protocol", "service", "honeypot", "severity", "event_type")
        with self.connect() as conn:
            for column in columns:
                rows = conn.execute(
                    f"""
                    SELECT {column} AS value, COUNT(*) AS count
                    FROM events
                    WHERE timestamp >= ? AND {column} IS NOT NULL AND {column} != ''
                    GROUP BY {column}
                    ORDER BY count DESC, value ASC
                    LIMIT 100
                    """,
                    (since,),
                ).fetchall()
                result[column] = [str(row["value"]) for row in rows]
        return result

    @staticmethod
    def _event_matches_filters(event: dict[str, Any], filters: dict[str, str] | None) -> bool:
        for key, value in (filters or {}).items():
            if value and key in _EVENT_FILTERS and str(event.get(key) or "") != value:
                return False
        return True

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

    @staticmethod
    def _top(events: list[dict[str, Any]], field: str, n: int = 10) -> list[dict[str, Any]]:
        counts = Counter(str(event.get(field)) for event in events if event.get(field) not in (None, ""))
        return [{"label": label, "value": value} for label, value in counts.most_common(n)]

    def dashboard(
        self,
        hours: int = 24,
        include_simulation: bool = False,
        q: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since,),
            ).fetchall()
        events = [self._decode(row) for row in rows]
        if not include_simulation:
            events = [event for event in events if event["derived"].get("data_mode") != "simulation"]
        events = [
            event for event in events
            if self._matches_q(event, q) and self._event_matches_filters(event, filters)
        ]

        timeline: dict[str, int] = defaultdict(int)
        heatmap = [[0 for _ in range(24)] for _ in range(7)]
        credentials, commands, mitre, ids = Counter(), Counter(), Counter(), Counter()
        for event in events:
            ts = datetime.fromisoformat(event["timestamp"])
            timeline[ts.strftime("%Y-%m-%dT%H:00Z")] += 1
            heatmap[ts.weekday()][ts.hour] += 1
            credential = event["observed"].get("credential")
            if isinstance(credential, dict) and credential.get("username"):
                credentials[str(credential["username"])] += 1
            if event["observed"].get("command"):
                commands[str(event["observed"]["command"])[:120]] += 1
            for item in event["derived"].get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            if event["event_type"] == "ids.alert":
                alert = event["observed"].get("alert") if isinstance(event["observed"].get("alert"), dict) else {}
                signature = event["observed"].get("signature") or alert.get("signature")
                if signature:
                    ids[str(signature)[:160]] += 1

        return {
            "window_hours": bounded_hours,
            "query": q or "",
            "filters": {key: value for key, value in (filters or {}).items() if value},
            "totals": {
                "events": len(events),
                "unique_source_ip": len({event["source_ip"] for event in events if event.get("source_ip")}),
                "sessions": len({event["session_id"] for event in events}),
                "critical": sum(1 for event in events if event["severity"] == "critical"),
            },
            "timeline": [{"label": key, "value": timeline[key]} for key in sorted(timeline)],
            "heatmap": heatmap,
            "country": self._top(events, "country"),
            "asn": self._top(events, "asn"),
            "destination_port": self._top(events, "destination_port"),
            "protocol": self._top(events, "protocol"),
            "service": self._top(events, "service"),
            "honeypot": self._top(events, "honeypot"),
            "credentials": [{"label": key, "value": value} for key, value in credentials.most_common(10)],
            "commands": [{"label": key, "value": value} for key, value in commands.most_common(10)],
            "ids_alerts": [{"label": key, "value": value} for key, value in ids.most_common(10)],
            "mitre": [{"label": key, "value": value} for key, value in mitre.most_common(10)],
            "map_points": [
                {
                    "lat": event["latitude"],
                    "lon": event["longitude"],
                    "source_ip": event["source_ip"],
                    "country": event["country"],
                    "event_id": event["id"],
                    "session_id": event["session_id"],
                }
                for event in events
                if event.get("latitude") is not None and event.get("longitude") is not None
            ][-400:],
        }

    def report(self, session_id: str) -> dict[str, Any] | None:
        bundle = self.get_session(session_id)
        if not bundle:
            return None
        events = bundle["events"]
        credentials, commands, payloads, iocs, mappings, enrichments = [], [], [], [], [], []
        for event in events:
            credential = event["observed"].get("credential")
            if isinstance(credential, dict):
                credentials.append({
                    "event_id": event["id"],
                    "username": credential.get("username"),
                    "password_length": credential.get("password_length"),
                    "password_sha256": credential.get("password_sha256"),
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
        return {
            "report_type": "investigation_session",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session": bundle["session"],
            "summary": bundle["summary"],
            "facts": {
                "event_count": len(events),
                "event_types": sorted({event["event_type"] for event in events}),
                "source_ips": sorted({event["source_ip"] for event in events if event.get("source_ip")}),
                "services": sorted({event["service"] for event in events if event.get("service")}),
                "protocols": sorted({event["protocol"] for event in events if event.get("protocol")}),
                "destination_ports": sorted({
                    event["destination_port"] for event in events if event.get("destination_port")
                }),
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
                "Credential exports never include cleartext passwords, even when raw credential storage was explicitly enabled.",
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

        for event in bundle["events"]:
            event_node = add("event", event["id"])
            session_node = add("session", event["session_id"])
            ip_node = add("ip", event.get("source_ip"))
            asn_node = add("asn", event.get("asn"))
            country_node = add("country", event.get("country"))
            port_node = add("port", event.get("destination_port"))
            protocol_node = add("protocol", event.get("protocol"))
            service_node = add("service", event.get("service"))
            honeypot_node = add("honeypot", event.get("honeypot"))
            credential = event["observed"].get("credential")
            credential = credential if isinstance(credential, dict) else {}
            user_node = add("credential", credential.get("username"))
            command_node = add("command", event["observed"].get("command"))
            payload_node = add("payload", event["observed"].get("payload"))

            alert = event["observed"].get("alert")
            alert = alert if isinstance(alert, dict) else {}
            alert_node = add("ids", alert.get("signature"))

            for target, relation in [
                (session_node, "belongs_to"),
                (ip_node, "source"),
                (asn_node, "enriched_asn"),
                (country_node, "enriched_country"),
                (port_node, "targets_port"),
                (protocol_node, "uses_protocol"),
                (service_node, "targets_service"),
                (honeypot_node, "observed_by"),
                (user_node, "uses_username"),
                (command_node, "observed_command"),
                (payload_node, "observed_payload"),
                (alert_node, "ids_alert"),
            ]:
                if event_node and target:
                    edges.add((event_node, target, relation))

            for item in event["derived"].get("mitre", []) or []:
                mitre_node = add("mitre", item.get("technique_id") if isinstance(item, dict) else None)
                if event_node and mitre_node:
                    edges.add((event_node, mitre_node, "mapped_with_evidence"))

            for item in event["derived"].get("cve", []) or []:
                cve_node = add("cve", item.get("cve_id") if isinstance(item, dict) else None)
                if event_node and cve_node:
                    edges.add((event_node, cve_node, "correlated_with_evidence"))

            for ioc in event["derived"].get("ioc", []) or []:
                ioc_node = add("ioc", ioc.get("value") if isinstance(ioc, dict) else ioc)
                if event_node and ioc_node:
                    edges.add((event_node, ioc_node, "derived_ioc"))

        return {
            "nodes": list(nodes.values()),
            "edges": [
                {"source": source, "target": target, "relation": relation}
                for source, target, relation in sorted(edges)
            ],
        }
