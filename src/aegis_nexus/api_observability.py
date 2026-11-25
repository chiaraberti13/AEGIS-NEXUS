"""Observability API routes for AEGIS-NEXUS.

Twelfth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the read-only operational views —
operations status (collector health + sensor telemetry freshness + counters),
Prometheus metrics, sensor health and the operator audit log.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). These endpoints are read-only;
``config`` is read through ``current_app`` to avoid capturing a stale reference.
The ``/`` index, ``/health`` liveness and ``/api/v1/operator/status`` routes
stay in the app factory (base/identity surface), as does the authenticated
sensor-heartbeat ingest.
"""

from __future__ import annotations

from flask import Blueprint, Response, current_app, jsonify, request

from .metrics import CONTENT_TYPE as PROMETHEUS_CONTENT_TYPE
from .metrics import render_prometheus


def make_observability_blueprint(*, store, audit_log) -> Blueprint:
    """Build the observability blueprint.

    ``store`` is the composed :class:`Store`; ``audit_log`` is the
    :class:`OperatorAuditLog`. Both are passed in explicitly so the blueprint
    has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("observability", __name__)

    def _sensor_health_snapshot(database_ready: bool) -> dict:
        if not database_ready:
            return {}
        return store.sensor_health(
            configured_sensor_ids=list(current_app.config.get("SENSOR_KEYS") or {}),
            recent_hours=24,
            heartbeat_stale_seconds=int(current_app.config.get("SENSOR_HEARTBEAT_STALE_SECONDS", 180)),
        )

    @bp.get("/api/v1/operations/status")
    def operations_status():
        health = store.operational_health(int(current_app.config.get("MIN_FREE_BYTES", 67_108_864)))
        telemetry = {
            "recent_hours": max(1, min(request.args.get("hours", 24, type=int), 720)),
            "configured_sensors": 0,
            "configured_with_recent_telemetry": 0,
            "observed_sensor_ids": 0,
            "items": [],
            "interpretation": "Telemetry freshness unavailable because the collector database is not ready.",
        }
        counters: dict = {}
        if health["database_ready"]:
            sensor_keys = current_app.config.get("SENSOR_KEYS") or {}
            telemetry = store.sensor_telemetry_observation(
                configured_sensor_ids=list(sensor_keys),
                recent_hours=request.args.get("hours", 24, type=int),
                heartbeat_stale_seconds=int(current_app.config.get("SENSOR_HEARTBEAT_STALE_SECONDS", 180)),
            )
            counters = store.counters()
        return jsonify({"collector": health, "telemetry": telemetry, "counters": counters})

    @bp.get("/api/v1/metrics")
    def platform_metrics():
        health = store.operational_health(int(current_app.config.get("MIN_FREE_BYTES", 67_108_864)))
        telemetry: dict = {}
        evidence_loss: dict | None = None
        snapshot = _sensor_health_snapshot(health["database_ready"])
        if snapshot:
            telemetry = {**snapshot["observation"], "silent_sensors_count": snapshot["silent_count"]}
        counters = None
        if health["database_ready"]:
            evidence_loss = store.evidence_loss_summary(hours=24)
            counters = store.counters()
        return Response(
            render_prometheus(health, telemetry, evidence_loss, counters),
            content_type=PROMETHEUS_CONTENT_TYPE,
        )

    @bp.get("/api/v1/sensors/health")
    def sensors_health():
        health = store.operational_health(int(current_app.config.get("MIN_FREE_BYTES", 67_108_864)))
        snapshot = _sensor_health_snapshot(health["database_ready"])
        if not snapshot:
            return jsonify({
                "recent_hours": 24, "sensors": [], "silent_sensors": [], "silent_count": 0,
                "interpretation": "Sensor health unavailable because the collector database is not ready.",
            })
        snapshot.pop("observation", None)  # already summarized into the sensors list
        return jsonify(snapshot)

    @bp.get("/api/v1/audit")
    def operator_audit():
        return jsonify({
            "retention_days": audit_log.retention_days,
            "max_rows": audit_log.max_rows,
            "items": audit_log.list(
                limit=request.args.get("limit", 200, type=int),
                operator=request.args.get("operator", type=str),
                action=request.args.get("action", type=str),
                target_type=request.args.get("target_type", type=str),
                target_id=request.args.get("target_id", type=str),
            ),
        })

    return bp
