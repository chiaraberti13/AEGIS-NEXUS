"""SOC summary report: a windowed roll-up composed from existing aggregations.

The 24h / 7d / 30d / custom reports are all the same report over different time
windows (``hours``). This module composes the event dashboard, per-rule
detection statistics, MTTA/MTTR response metrics and the ATT&CK rule-coverage
view into one evidence-first summary, and surfaces Evidence Integrity warnings
explicitly so a clean-looking summary never hides lossy normalization or a
capped analytics window.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .detection_config import DetectionConfig
from .detection_coverage import mitre_coverage

SOC_SUMMARY_SCHEMA_VERSION = "1.0"

# data_quality keys from the dashboard that represent evidence loss/transformation.
_INTEGRITY_KEYS = (
    "events_with_truncation",
    "events_with_lossy_normalization",
    "events_with_credential_redaction",
    "truncated_strings",
    "truncated_collections",
    "dropped_keys",
    "coerced_values",
    "credential_secrets_redacted",
    "events_with_sensor_truncation",
    "events_with_sensor_rejection",
    "sensor_truncated_fields",
)

NAMED_WINDOWS = {"24h": 24, "7d": 168, "30d": 720}


def build_soc_summary(store: Any, alert_store: Any, detection_config: DetectionConfig, *, hours: int) -> dict[str, Any]:
    bounded = max(1, min(int(hours), 8760))
    dashboard = store.dashboard(hours=bounded)
    stats = alert_store.statistics(hours=bounded)
    response = alert_store.response_metrics(hours=bounded)
    coverage = mitre_coverage(detection_config)

    totals = dashboard.get("totals", {})
    data_quality = dashboard.get("data_quality", {})
    analysis = dashboard.get("analysis", {})

    warnings: list[dict[str, Any]] = [
        {"kind": key, "count": int(data_quality.get(key) or 0)}
        for key in _INTEGRITY_KEYS
        if int(data_quality.get(key) or 0) > 0
    ]
    if analysis.get("truncated"):
        warnings.append(
            {
                "kind": "analytics_window_capped",
                "detail": f"analytics limited to the latest {analysis.get('event_limit')} matching events; "
                "totals in this window may under-count",
            }
        )

    alert_total = sum(int(rule.get("alerts") or 0) for rule in stats.get("rules", []))
    alert_open = sum(int(rule.get("open") or 0) for rule in stats.get("rules", []))

    return {
        "schema_version": SOC_SUMMARY_SCHEMA_VERSION,
        "report_type": "soc_summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_hours": bounded,
        "events": {
            "total": int(totals.get("events") or 0),
            "unique_source_ip": int(totals.get("unique_source_ip") or 0),
            "sessions": int(totals.get("sessions") or 0),
            "critical": int(totals.get("critical") or 0),
            "by_severity": dashboard.get("severity", []),
            "top_countries": dashboard.get("country", []),
            "top_asns": dashboard.get("asn", []),
            "top_source_ips": dashboard.get("source_ip", []),
        },
        "detections": {
            "alert_total": alert_total,
            "alert_open": alert_open,
            "rules": stats.get("rules", []),
            "response": response,
        },
        "iocs": dashboard.get("iocs", []),
        "mitre": {
            "observed": dashboard.get("mitre", []),
            "rule_coverage": coverage.get("techniques", []),
        },
        "evidence_integrity_warnings": warnings,
        "caveats": [
            "Counts describe telemetry observed in the window; geolocation/ASN are "
            "enrichment, not identity, and MITRE/IOC entries are evidence-backed, "
            "never attribution.",
            "Evidence integrity warnings disclose lossy normalization and capped "
            "analytics; an empty list is not a guarantee of completeness.",
            "MTTA/MTTR reflect analyst response latency, not detector accuracy.",
        ],
    }
