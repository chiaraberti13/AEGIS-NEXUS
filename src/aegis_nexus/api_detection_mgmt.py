"""Detection-management API routes for AEGIS-NEXUS.

Seventh domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): rule backtesting and the detection
suppression lifecycle (list, create, delete, audit). Distinct from the
read-only detection-posture endpoints in ``api_detections.py``.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). Suppression mutations are
validated and audited inside ``DetectionSuppressionStore`` (actor recorded);
backtesting is read-only replay over stored events and never mutates alerts.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .detection_suppression import SuppressionValidationError


def make_detection_management_blueprint(
    *,
    store,
    detection_config,
    detection_backtester,
    detection_suppressions,
) -> Blueprint:
    """Build the ``/api/v1/detection`` management blueprint.

    All collaborators (``store``, the loaded ``detection_config``, the
    ``detection_backtester`` and the ``detection_suppressions`` store) are passed
    in explicitly so the blueprint has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("detection_management", __name__)

    @bp.post("/api/v1/detection/backtest")
    def detection_backtest():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "validation_error"}), 422
        rule_id = str(payload.get("rule_id") or "").strip() or None
        if rule_id and rule_id not in detection_config.rules:
            return jsonify({"error": "validation_error", "detail": "unknown_detection_rule"}), 422
        try:
            hours = int(payload.get("hours", 24))
            max_events = int(payload.get("max_events", 5000))
        except (TypeError, ValueError):
            return jsonify({"error": "validation_error", "detail": "hours and max_events must be integers"}), 422
        return jsonify(detection_backtester.run_store(
            store,
            hours=hours,
            rule_id=rule_id,
            max_events=max_events,
        ))

    @bp.get("/api/v1/detection/suppressions")
    def detection_suppression_list():
        return jsonify({
            "items": detection_suppressions.list(
                active_only=request.args.get("active_only", "false").lower() in {"1", "true", "yes"},
                limit=request.args.get("limit", 200, type=int),
            )
        })

    @bp.post("/api/v1/detection/suppressions")
    def detection_suppression_create():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "validation_error"}), 422
        try:
            item = detection_suppressions.create(
                rule_id=payload.get("rule_id", ""),
                source_ip=payload.get("source_ip"),
                owner=payload.get("owner", ""),
                reason=payload.get("reason", ""),
                expires_at=payload.get("expires_at", ""),
                actor=payload.get("owner", ""),
            )
        except SuppressionValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        return jsonify(item), 201

    @bp.delete("/api/v1/detection/suppressions/<suppression_id>")
    def detection_suppression_delete(suppression_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        payload = request.get_json()
        actor = payload.get("actor") if isinstance(payload, dict) else None
        try:
            deleted = detection_suppressions.delete(suppression_id[:128], actor=actor or "")
        except SuppressionValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        return ("", 204) if deleted else (jsonify({"error": "not_found"}), 404)

    @bp.get("/api/v1/detection/suppressions/audit")
    def detection_suppression_audit():
        return jsonify({
            "items": detection_suppressions.audit(
                suppression_id=request.args.get("suppression_id", type=str),
                limit=request.args.get("limit", 500, type=int),
            )
        })

    return bp
