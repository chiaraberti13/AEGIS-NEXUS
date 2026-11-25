"""Alert triage API routes for AEGIS-NEXUS.

Eighth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the alert response metrics, the alert
list and detail, status/tag/disposition updates and operator notes.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). Status/tag/disposition updates
and note additions are written to the operator audit log via the injected
``record_audit``; note bodies are operator free text and are never copied into
the audit trail (only attribution and length).
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, jsonify, request


def make_alerts_blueprint(*, alert_store, record_audit: Callable) -> Blueprint:
    """Build the ``/api/v1/alerts`` blueprint.

    ``alert_store`` is the :class:`AlertStore`; ``record_audit`` is the app's
    operator-audit writer. Both are passed in explicitly so the blueprint has no
    import-time coupling to ``create_app``.
    """
    bp = Blueprint("alerts", __name__)

    @bp.get("/api/v1/alerts/metrics")
    def alert_response_metrics():
        hours = request.args.get("hours", type=int)
        return jsonify(alert_store.response_metrics(hours=hours))

    @bp.get("/api/v1/alerts")
    def alerts():
        return jsonify({
            "items": alert_store.list(
                limit=request.args.get("limit", 100, type=int),
                status=request.args.get("status", type=str),
                severity=request.args.get("severity", type=str),
            )
        })

    @bp.get("/api/v1/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        item = alert_store.get(alert_id[:128])
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @bp.patch("/api/v1/alerts/<alert_id>")
    def update_alert(alert_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "validation_error"}), 422
        status = payload.get("status")
        tags = payload.get("tags")
        disposition = payload.get("disposition")
        if tags is not None and (not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags)):
            return jsonify({"error": "validation_error", "detail": "tags must be a list of strings"}), 422
        if disposition is not None and not isinstance(disposition, str):
            return jsonify({"error": "validation_error", "detail": "disposition must be a string"}), 422
        try:
            item = alert_store.update(alert_id[:128], status=status, tags=tags, disposition=disposition)
        except ValueError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        if not item:
            return jsonify({"error": "not_found"}), 404
        detail: dict = {}
        if status is not None:
            detail["status"] = item.get("status")
        if tags is not None:
            detail["tag_count"] = len(item.get("tags") or [])
        if disposition is not None:
            detail["disposition"] = item.get("disposition")
        record_audit(
            "alert.update",
            target_type="alert",
            target_id=alert_id[:128],
            detail=detail,
        )
        return jsonify(item), 200

    @bp.post("/api/v1/alerts/<alert_id>/notes")
    def add_alert_note(alert_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        payload = request.get_json()
        body = payload.get("body") if isinstance(payload, dict) else None
        try:
            item = alert_store.add_note(alert_id[:128], body or "")
        except ValueError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        if not item:
            return jsonify({"error": "not_found"}), 404
        # Attribution and length only: the note body is operator free text and is
        # not copied into the audit trail.
        record_audit(
            "alert.note_add",
            target_type="alert",
            target_id=alert_id[:128],
            detail={"body_length": len(body or "")},
        )
        return jsonify(item), 201

    return bp
