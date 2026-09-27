from __future__ import annotations

from collections import Counter
from typing import Any

from .detection import DetectionEngine


class DetectionBacktester:
    """Read-only deterministic replay of detection rules over retained events."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def run(
        self,
        events: list[dict[str, Any]],
        *,
        rule_id: str | None = None,
        max_events: int = 5000,
    ) -> dict[str, Any]:
        bounded = max(1, min(int(max_events), 5000))
        ordered = sorted(
            events[:bounded],
            key=lambda item: (str(item.get("timestamp") or ""), str(item.get("id") or "")),
        )
        hits: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        history: list[dict[str, Any]] = []
        for event in ordered:
            findings = self.engine.evaluate(event, history)
            for finding in findings:
                if rule_id and finding.get("rule_id") != rule_id:
                    continue
                counts[str(finding.get("rule_id") or "unknown")] += 1
                hits.append({
                    "event_id": event.get("id"),
                    "timestamp": event.get("timestamp"),
                    "rule_id": finding.get("rule_id"),
                    "rule_version": finding.get("rule_version"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "source_ip": finding.get("source_ip"),
                    "session_id": finding.get("session_id"),
                    "evidence": list(finding.get("evidence") or []),
                })
            history.append(event)

        return {
            "mode": "read_only_detection_backtest",
            "events_evaluated": len(ordered),
            "truncated": len(events) > bounded,
            "rule_filter": rule_id,
            "rule_hit_counts": dict(sorted(counts.items())),
            "total_hits": len(hits),
            "hits": hits[:2000],
            "hit_output_truncated": len(hits) > 2000,
            "detection_config": self.engine.config.public(),
            "writes_alerts": False,
            "applies_suppressions": False,
        }

    def run_store(
        self,
        store: Any,
        *,
        hours: int = 24,
        rule_id: str | None = None,
        max_events: int = 5000,
    ) -> dict[str, Any]:
        bounded_hours = max(1, min(int(hours), 720))
        bounded_events = max(1, min(int(max_events), 5000))
        items: list[dict[str, Any]] = []
        cursor = None
        while len(items) < bounded_events:
            page = store.page_events(
                limit=min(500, bounded_events - len(items)),
                hours=bounded_hours if cursor is None else None,
                cursor=cursor,
                scope="detection-backtest",
            )
            items.extend(page["items"])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        result = self.run(items, rule_id=rule_id, max_events=bounded_events)
        result["source"] = "stored_history"
        result["hours"] = bounded_hours
        result["history_has_more"] = bool(cursor)
        return result
