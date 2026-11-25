"""Constants shared across the storage modules.

A dependency-free leaf module so the ``Store`` backend and the extracted
storage-domain mixins (``store_analytics``, ``store_cases``, …) can share
vocabulary without importing each other (ADR 0003). It must not import any
other ``aegis_nexus`` module, so it never participates in an import cycle.
"""

from __future__ import annotations

# Event fields that may be filtered on, both in SQL (`Store._sql_filters`) and
# in the client-side analytics filter (`AnalyticsStoreMixin._event_matches_filters`).
EVENT_FILTERS: tuple[str, ...] = (
    "country",
    "asn",
    "destination_port",
    "protocol",
    "service",
    "honeypot",
    "severity",
    "source_ip",
    "session_id",
    "event_type",
)
