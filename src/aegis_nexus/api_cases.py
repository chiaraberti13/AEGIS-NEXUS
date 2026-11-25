"""Case management API routes for AEGIS-NEXUS.

Tenth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the analyst case CRUD, evidence links,
notes and the case timeline.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). Every mutation is written to
the operator audit log via the injected ``record_audit``; new cases default
their owner to the acting operator (injected identity helpers). Note bodies are
operator free text and are intentionally not stored in the audit trail. Input is
normalized/validated through ``casework`` before it reaches the store.
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, jsonify, request

from .casework import (
    CaseValidationError,
    normalize_case_create,
    normalize_case_update,
    normalize_evidence,
    normalize_note,
)


def make_cases_blueprint(
    *,
    store,
    record_audit: Callable,
    current_operator_identity: Callable[[], str | None],
    default_operator_identity: Callable[[], str],
) -> Blueprint:
    """Build the ``/api/v1/cases`` blueprint.

    ``store`` is the composed :class:`Store`; ``record_audit`` the operator-audit
    writer; ``current_operator_identity`` / ``default_operator_identity`` the
    app's identity helpers used to default new-case ownership. All are passed in
    explicitly so the blueprint has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("cases", __name__)

    @bp.get("/api/v1/cases")
    def cases():
        return jsonify({
            "items": store.list_cases(
                limit=request.args.get("limit", 100, type=int),
                q=request.args.get("q", type=str),
                status=request.args.get("status", type=str),
            )
        })

    @bp.post("/api/v1/cases")
    def create_case():
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            case_data = normalize_case_create(request.get_json())
            if not case_data.get("owner"):
                # Default ownership to the acting operator (Cycle P identity).
                case_data["owner"] = current_operator_identity() or default_operator_identity()
            item = store.create_case(case_data)
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except ValueError as exc:
            if str(exc) == "case_capacity":
                return jsonify({"error": "case_capacity"}), 409
            raise
        record_audit(
            "case.create",
            target_type="case",
            target_id=str(item.get("id") or "")[:128],
            detail={
                "status": item.get("status"),
                "severity": item.get("severity"),
                "priority": item.get("priority"),
                "owner": item.get("owner"),
            },
        )
        return jsonify(item), 201

    @bp.get("/api/v1/cases/<case_id>")
    def case_detail(case_id: str):
        item = store.get_case(case_id[:128])
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @bp.get("/api/v1/cases/<case_id>/timeline")
    def case_timeline(case_id: str):
        item = store.case_timeline(case_id[:128])
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @bp.delete("/api/v1/cases/<case_id>")
    def delete_case(case_id: str):
        result = store.delete_case(case_id[:128])
        if result == "not_found":
            return jsonify({"error": "not_found"}), 404
        if result == "case_not_closed":
            return jsonify({"error": "case_not_closed"}), 409
        record_audit("case.delete", target_type="case", target_id=case_id[:128])
        return ("", 204)

    @bp.patch("/api/v1/cases/<case_id>")
    def update_case(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            item = store.update_case(case_id[:128], normalize_case_update(request.get_json()))
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        if not item:
            return jsonify({"error": "not_found"}), 404
        record_audit(
            "case.update",
            target_type="case",
            target_id=case_id[:128],
            detail={"status": item.get("status"), "severity": item.get("severity")},
        )
        return jsonify(item), 200

    @bp.post("/api/v1/cases/<case_id>/evidence")
    def add_case_evidence(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            evidence = normalize_evidence(request.get_json())
            item = store.add_case_evidence(case_id[:128], evidence["type"], evidence["id"])
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except ValueError as exc:
            if str(exc) == "evidence_not_found":
                return jsonify({"error": "evidence_not_found"}), 404
            if str(exc) == "case_evidence_limit":
                return jsonify({"error": "case_evidence_limit"}), 422
            raise
        if not item:
            return jsonify({"error": "not_found"}), 404
        record_audit(
            "case.evidence_add",
            target_type="case",
            target_id=case_id[:128],
            detail={"evidence_type": evidence["type"], "evidence_id": evidence["id"]},
        )
        return jsonify(item), 200

    @bp.delete("/api/v1/cases/<case_id>/evidence/<int:evidence_row_id>")
    def remove_case_evidence(case_id: str, evidence_row_id: int):
        try:
            item = store.remove_case_evidence(case_id[:128], evidence_row_id)
        except ValueError as exc:
            if str(exc) == "evidence_not_found":
                return jsonify({"error": "evidence_not_found"}), 404
            raise
        if not item:
            return jsonify({"error": "not_found"}), 404
        record_audit(
            "case.evidence_remove",
            target_type="case",
            target_id=case_id[:128],
            detail={"evidence_row_id": int(evidence_row_id)},
        )
        return jsonify(item), 200

    @bp.post("/api/v1/cases/<case_id>/notes")
    def add_case_note(case_id: str):
        if not request.is_json:
            return jsonify({"error": "content_type_must_be_json"}), 415
        try:
            item = store.add_case_note(case_id[:128], normalize_note(request.get_json()))
        except CaseValidationError as exc:
            return jsonify({"error": "validation_error", "detail": str(exc)}), 422
        except ValueError as exc:
            if str(exc) == "case_note_limit":
                return jsonify({"error": "case_note_limit"}), 422
            raise
        if not item:
            return jsonify({"error": "not_found"}), 404
        # The note body is operator free text and is intentionally not stored.
        record_audit("case.note_add", target_type="case", target_id=case_id[:128])
        return jsonify(item), 201

    return bp
