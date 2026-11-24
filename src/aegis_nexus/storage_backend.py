"""Storage backend interface.

Defines the storage surface the collector depends on, so that alternative
backends can be introduced without changing investigation semantics. ``Store``
(raw SQLite, WAL) is the **reference implementation** and the only backend
currently shipped; a PostgreSQL backend is future work tracked by
``docs/adr/0002-storage-backend-postgresql.md`` (it requires porting the
SQLite-specific migration/integrity/hash-chain machinery and cannot be shipped
unverified).

The Protocol is ``runtime_checkable`` so conformance of a concrete backend can
be asserted in tests. It intentionally captures the core data-plane surface
(the methods the API and analytics call), not every private helper.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# The core methods a storage backend must provide. Kept as a named tuple so
# tests and documentation share one source of truth.
REQUIRED_METHODS: tuple[str, ...] = (
    # ingest & events
    "ingest",
    "get_event",
    "page_events",
    "detection_context",
    "behavioral_context",
    # analytics & dashboards
    "dashboard",
    "filter_options",
    "evidence_loss_summary",
    # operations / health
    "operational_health",
    "sensor_telemetry_observation",
    "sensor_health",
    "record_sensor_heartbeat",
    "reserve_sensor_nonce",
    "counters",
    "increment_counter",
    # cases
    "create_case",
    "get_case",
    "update_case",
    "delete_case",
    "list_cases",
    "add_case_evidence",
    "case_report",
    "case_timeline",
    # retention / maintenance
    "prune_cases",
    "set_ioc_resolver",
)


@runtime_checkable
class StorageBackend(Protocol):
    """Structural interface for a collector storage backend.

    Any object providing these methods (``Store`` does) satisfies the backend
    contract. See ``REQUIRED_METHODS`` for the authoritative list used by the
    conformance test.
    """

    def ingest(self, event: dict[str, Any], *, collector_received_at: str) -> dict[str, Any]: ...
    def get_event(self, event_id: str) -> dict[str, Any] | None: ...
    def dashboard(self, **kwargs: Any) -> dict[str, Any]: ...
    def operational_health(self, min_free_bytes: int = ...) -> dict[str, Any]: ...
    def create_case(self, data: dict[str, Any]) -> dict[str, Any]: ...
    def get_case(self, case_id: str) -> dict[str, Any] | None: ...
    def counters(self) -> dict[str, int]: ...
    def increment_counter(self, name: str, by: int = ...) -> None: ...
