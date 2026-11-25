"""Analytics & dashboard storage domain for :class:`~aegis_nexus.store.Store`.

Extracted from ``store.py`` as an incremental Cycle I storage split (ADR 0003).
The read-only analytical aggregations — the geospatial attack rollup, the
evidence-loss summary, filter options, the client-side filter/search helpers and
the main dashboard projection — live here as a mixin that ``Store`` composes, so
the public API (``Store(...).dashboard(...)`` etc.) and its behaviour are
unchanged (guarded by the API-contract and dashboard tests).

The mixin relies, through ``self``, on the composed ``Store`` for the shared
connection (``connect``), row decoding (``_decode``), SQL filter building
(``_sql_filters``), small projection helpers (``_counter_items``,
``_credential_secret_summary``) and the bounded analytics window
(``analytics_max_events``). It is strictly read/aggregate: it keeps the
evidence-first provenance split intact and never re-derives or attributes.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .store_common import EVENT_FILTERS


class AnalyticsStoreMixin:
    def geo_attacks(
        self,
        hours: int = 24,
        filters: dict[str, str] | None = None,
        max_points: int = 500,
    ) -> dict[str, Any]:
        """Aggregate approximate attack origins for geospatial visualization.

        Coordinates are GeoIP **enrichment**, not identity or attribution, and
        are coarsened to ~2 decimals for grouping. Events whose source IP has no
        geolocation (private, non-global or simply not in the database) are not
        dropped: they are counted in an explicit ``unmapped`` bucket (evidence
        completeness). The point list is hard-capped.
        """
        _SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        bounded_hours = max(1, min(int(hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        cap = max(1, min(int(max_points), 2000))
        clauses = ["timestamp >= ?"]
        params: list[Any] = [since]
        filter_clauses, filter_params = self._sql_filters(filters)
        clauses.extend(filter_clauses)
        params.extend(filter_params)
        params.append(self.analytics_max_events)
        where = " AND ".join(clauses)

        points: dict[tuple[float, float], dict[str, Any]] = {}
        unmapped_ips: set[str] = set()
        unmapped_events = 0
        considered = 0
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT source_ip, latitude, longitude, country, asn, severity,
                       session_id, timestamp, enrichment
                FROM events WHERE {where}
                ORDER BY timestamp DESC LIMIT ?
                """,
                params,
            ).fetchall()
        for row in rows:
            considered += 1
            source_ip = row["source_ip"]
            lat, lon = row["latitude"], row["longitude"]
            if lat is None or lon is None:
                if source_ip:
                    unmapped_events += 1
                    unmapped_ips.add(str(source_ip))
                continue
            key = (round(float(lat), 2), round(float(lon), 2))
            point = points.get(key)
            if point is None:
                point = {
                    "lat": key[0], "lon": key[1], "country": row["country"], "asn": row["asn"],
                    "count": 0, "severity_level": 0, "last_seen": row["timestamp"],
                    "accuracy_radius_km": None,
                    "_ips": set(), "_sessions": set(),
                }
                points[key] = point
            point["count"] += 1
            point["severity_level"] = max(point["severity_level"], _SEVERITY.get(str(row["severity"]), 0))
            if source_ip:
                point["_ips"].add(str(source_ip))
            if row["session_id"]:
                point["_sessions"].add(str(row["session_id"]))
            if row["timestamp"] and str(row["timestamp"]) > str(point["last_seen"]):
                point["last_seen"] = row["timestamp"]
            try:
                enrichment = json.loads(row["enrichment"] or "{}")
                radius = (enrichment.get("geo") or {}).get("data", {}).get("accuracy_radius_km")
                if radius is not None:
                    radius = int(radius)
                    if point["accuracy_radius_km"] is None or radius > point["accuracy_radius_km"]:
                        point["accuracy_radius_km"] = radius
            except (TypeError, ValueError, json.JSONDecodeError):
                pass

        ordered = sorted(points.values(), key=lambda p: (p["count"], p["severity_level"]), reverse=True)
        truncated = len(ordered) > cap
        result_points = []
        for point in ordered[:cap]:
            result_points.append({
                "lat": point["lat"], "lon": point["lon"],
                "country": point["country"], "asn": point["asn"],
                "count": point["count"],
                "unique_source_ips": len(point["_ips"]),
                "session_count": len(point["_sessions"]),
                "severity_level": point["severity_level"],
                "accuracy_radius_km": point["accuracy_radius_km"],
                "last_seen": point["last_seen"],
            })
        return {
            "schema_version": "1.0",
            "window_hours": bounded_hours,
            "provenance": "enrichment",
            "events_considered": considered,
            "events_truncated_at_limit": considered >= self.analytics_max_events,
            "points": result_points,
            "points_truncated": truncated,
            "point_cap": cap,
            "unmapped": {
                "events": unmapped_events,
                "unique_source_ips": len(unmapped_ips),
                "reason": "source IP is private, non-global or has no GeoIP location",
            },
            "caveat": (
                "Coordinates are approximate GeoIP enrichment (city-level), not "
                "identity or attribution; VPN/proxy/Tor and shared hosting are "
                "common. Unmapped events are disclosed, never dropped."
            ),
        }

    def evidence_loss_summary(self, hours: int = 24) -> dict[str, Any]:
        """Normalization/evidence-loss counts over a bounded recent window.

        Single pass over the ``collector`` column of recent events (bounded by
        the analytics cap), summing the same disclosed loss counters the
        dashboard surfaces. Evidence loss is observed from stored provenance,
        never inferred.
        """
        bounded = max(1, min(int(hours), 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded)).isoformat()
        counts: Counter[str] = Counter()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT collector FROM events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
                (since, self.analytics_max_events),
            ).fetchall()
        for row in rows:
            try:
                collector = json.loads(row["collector"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            normalization = collector.get("normalization") if isinstance(collector, dict) else None
            if not isinstance(normalization, dict):
                continue
            sub = normalization.get("counts")
            sub = sub if isinstance(sub, dict) else {}
            for key in ("truncated_strings", "truncated_collections", "dropped_keys",
                        "coerced_values", "credential_secrets_redacted"):
                try:
                    counts[key] += max(0, int(sub.get(key) or 0))
                except (TypeError, ValueError):
                    continue
            if normalization.get("truncated"):
                counts["events_with_truncation"] += 1
            if normalization.get("lossy"):
                counts["events_with_lossy_normalization"] += 1
            if normalization.get("redacted"):
                counts["events_with_credential_redaction"] += 1
        return {
            "window_hours": bounded,
            "events_considered": len(rows),
            "truncated_at_limit": len(rows) >= self.analytics_max_events,
            "counts": {key: int(counts[key]) for key in sorted(counts)},
        }

    def filter_options(self, hours: int = 720) -> dict[str, list[str]]:
        bounded_hours = max(1, min(hours, 720))
        since = (datetime.now(timezone.utc) - timedelta(hours=bounded_hours)).isoformat()
        result: dict[str, list[str]] = {}
        columns = ("country", "asn", "destination_port", "protocol", "service", "honeypot", "severity", "event_type")
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
            if value and key in EVENT_FILTERS and str(event.get(key) or "") != value:
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
        clauses = ["timestamp >= ?"]
        params: list[Any] = [since]
        filter_clauses, filter_params = self._sql_filters(filters)
        clauses.extend(filter_clauses)
        params.extend(filter_params)
        if q:
            clauses.append(
                "(source_ip LIKE ? OR event_type LIKE ? OR honeypot LIKE ? OR protocol LIKE ? OR "
                "service LIKE ? OR country LIKE ? OR asn LIKE ? OR "
                "json_remove(observed, '$.credential.password') LIKE ? OR enrichment LIKE ? OR derived LIKE ?)"
            )
            needle = f"%{q[:128]}%"
            params.extend([needle] * 10)
        params.append(self.analytics_max_events + 1)
        where = " AND ".join(clauses)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        truncated = len(rows) > self.analytics_max_events
        if truncated:
            rows = rows[:self.analytics_max_events]
        events = [self._decode(row) for row in reversed(rows)]
        if not include_simulation:
            events = [event for event in events if event["derived"].get("data_mode") != "simulation"]

        timeline: dict[str, int] = defaultdict(int)
        unique_source_timeline: dict[str, set[str]] = defaultdict(set)
        heatmap = [[0 for _ in range(24)] for _ in range(7)]
        credentials, credential_secrets = Counter(), Counter()
        commands, payloads = Counter(), Counter()
        mitre, cves, ids, iocs = Counter(), Counter(), Counter(), Counter()
        normalization_counts: Counter[str] = Counter()
        sensor_capture_counts: Counter[str] = Counter()
        map_groups: dict[tuple[str, float, float], dict[str, Any]] = {}

        for event in events:
            normalization = (event.get("collector") or {}).get("normalization")
            if isinstance(normalization, dict):
                counts = normalization.get("counts")
                counts = counts if isinstance(counts, dict) else {}
                for key in (
                    "truncated_strings",
                    "truncated_collections",
                    "dropped_keys",
                    "coerced_values",
                    "credential_secrets_redacted",
                ):
                    try:
                        normalization_counts[key] += max(0, int(counts.get(key) or 0))
                    except (TypeError, ValueError):
                        continue
                if normalization.get("truncated"):
                    normalization_counts["events_with_truncation"] += 1
                if normalization.get("lossy"):
                    normalization_counts["events_with_lossy_normalization"] += 1
                if normalization.get("redacted"):
                    normalization_counts["events_with_credential_redaction"] += 1

            sensor_capture = (event.get("observed") or {}).get("sensor_capture")
            if isinstance(sensor_capture, dict):
                if sensor_capture.get("truncated"):
                    sensor_capture_counts["events_with_truncation"] += 1
                if sensor_capture.get("rejected"):
                    sensor_capture_counts["events_with_rejection"] += 1
                entries = sensor_capture.get("truncated_fields")
                if isinstance(entries, list):
                    sensor_capture_counts["truncated_fields"] += len(entries)

            ts = datetime.fromisoformat(event["timestamp"])
            bucket = ts.strftime("%Y-%m-%dT%H:00Z")
            timeline[bucket] += 1
            if event.get("source_ip"):
                unique_source_timeline[bucket].add(str(event["source_ip"]))
            heatmap[ts.weekday()][ts.hour] += 1
            credential = event["observed"].get("credential")
            if isinstance(credential, dict):
                if credential.get("username"):
                    credentials[str(credential["username"])] += 1
                secret = self._credential_secret_summary(credential)
                if secret:
                    credential_secrets[secret["label"]] += 1
            if event["observed"].get("command"):
                commands[str(event["observed"]["command"])[:120]] += 1
            if event["observed"].get("payload"):
                payloads[str(event["observed"]["payload"])[:120]] += 1
            for item in event["derived"].get("mitre", []) or []:
                if isinstance(item, dict) and item.get("technique_id"):
                    mitre[str(item["technique_id"])] += 1
            for item in event["derived"].get("cve", []) or []:
                if isinstance(item, dict) and item.get("cve_id"):
                    cves[str(item["cve_id"])] += 1
            for item in event["derived"].get("ioc", []) or []:
                if isinstance(item, dict) and item.get("type") and item.get("value") not in (None, ""):
                    label = f"{item['type']}: {str(item['value'])[:140]}"
                    iocs[label] += 1
            if event["event_type"] == "ids.alert":
                alert = event["observed"].get("alert") if isinstance(event["observed"].get("alert"), dict) else {}
                signature = event["observed"].get("signature") or alert.get("signature")
                if signature:
                    ids[str(signature)[:160]] += 1

            if (
                event.get("source_ip")
                and event.get("latitude") is not None
                and event.get("longitude") is not None
            ):
                lat = round(float(event["latitude"]), 4)
                lon = round(float(event["longitude"]), 4)
                map_key = (str(event["source_ip"]), lat, lon)
                point = map_groups.setdefault(map_key, {
                    "lat": lat,
                    "lon": lon,
                    "source_ip": event["source_ip"],
                    "country": event.get("country"),
                    "asn": event.get("asn"),
                    "count": 0,
                    "session_ids": set(),
                    "services": set(),
                    "destination_ports": set(),
                    "honeypots": set(),
                    "last_seen": event["timestamp"],
                })
                point["count"] += 1
                point["session_ids"].add(event["session_id"])
                if event.get("service"):
                    point["services"].add(event["service"])
                if event.get("destination_port"):
                    point["destination_ports"].add(event["destination_port"])
                if event.get("honeypot"):
                    point["honeypots"].add(event["honeypot"])
                if event["timestamp"] > point["last_seen"]:
                    point["last_seen"] = event["timestamp"]

        map_points = []
        for point in map_groups.values():
            map_points.append({
                "lat": point["lat"],
                "lon": point["lon"],
                "source_ip": point["source_ip"],
                "country": point["country"],
                "asn": point["asn"],
                "count": point["count"],
                "session_count": len(point["session_ids"]),
                "services": sorted(point["services"])[:8],
                "destination_ports": sorted(point["destination_ports"])[:16],
                "honeypots": sorted(point["honeypots"])[:8],
                "last_seen": point["last_seen"],
            })
        map_points.sort(key=lambda item: (int(item["count"]), str(item["last_seen"])), reverse=True)

        return {
            "window_hours": bounded_hours,
            "query": q or "",
            "filters": {key: value for key, value in (filters or {}).items() if value},
            "analysis": {
                "truncated": truncated,
                "event_limit": self.analytics_max_events,
                "scope": "latest_matching_events",
                "provenance": {
                    "observed": ["events", "source_ip", "destination_port", "protocol", "service", "honeypot", "credentials", "commands", "payloads", "ids_alerts"],
                    "enrichment": ["country", "asn", "map_points"],
                    "derived": ["sessions", "credential_secret_fingerprints", "iocs", "mitre", "cves"],
                    "collector": ["normalization"],
                    "hypotheses_in_analytics": False,
                },
            },
            "totals": {
                "events": len(events),
                "unique_source_ip": len({event["source_ip"] for event in events if event.get("source_ip")}),
                "sessions": len({event["session_id"] for event in events}),
                "critical": sum(1 for event in events if event["severity"] == "critical"),
            },
            "data_quality": {
                "events_with_truncation": int(normalization_counts["events_with_truncation"]),
                "events_with_lossy_normalization": int(normalization_counts["events_with_lossy_normalization"]),
                "events_with_credential_redaction": int(normalization_counts["events_with_credential_redaction"]),
                "truncated_strings": int(normalization_counts["truncated_strings"]),
                "truncated_collections": int(normalization_counts["truncated_collections"]),
                "dropped_keys": int(normalization_counts["dropped_keys"]),
                "coerced_values": int(normalization_counts["coerced_values"]),
                "credential_secrets_redacted": int(normalization_counts["credential_secrets_redacted"]),
                "events_with_sensor_truncation": int(sensor_capture_counts["events_with_truncation"]),
                "events_with_sensor_rejection": int(sensor_capture_counts["events_with_rejection"]),
                "sensor_truncated_fields": int(sensor_capture_counts["truncated_fields"]),
            },
            "timeline": [{"label": key, "value": timeline[key]} for key in sorted(timeline)],
            "unique_source_ip_timeline": [
                {"label": key, "value": len(unique_source_timeline[key])}
                for key in sorted(unique_source_timeline)
            ],
            "heatmap": heatmap,
            "source_ip": self._top(events, "source_ip"),
            "event_type": self._top(events, "event_type"),
            "severity": self._top(events, "severity"),
            "country": self._top(events, "country"),
            "asn": self._top(events, "asn"),
            "destination_port": self._top(events, "destination_port"),
            "protocol": self._top(events, "protocol"),
            "service": self._top(events, "service"),
            "honeypot": self._top(events, "honeypot"),
            "credentials": self._counter_items(credentials),
            "credential_secret_fingerprints": self._counter_items(credential_secrets),
            "commands": self._counter_items(commands),
            "payloads": self._counter_items(payloads),
            "ids_alerts": self._counter_items(ids),
            "iocs": self._counter_items(iocs),
            "mitre": self._counter_items(mitre),
            "cves": self._counter_items(cves),
            "map_points": map_points[:400],
        }
