"""PCAP evidence API routes for AEGIS-NEXUS.

Fifth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): listing, operator upload, on-demand
capture and authenticated download of bounded PCAP evidence.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes), so it is not repeated inline.
Every mutation or download is written to the operator audit log via the injected
``record_audit`` callable. The store enforces size/retention bounds and verifies
the SHA-256 on read; the capture provider is disabled by default. ``config`` is
read through ``current_app`` to avoid capturing a stale reference.
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, Response, current_app, jsonify, request

from .pcap import PcapValidationError


def make_pcap_blueprint(*, pcap_store, pcap_capture_provider, record_audit: Callable) -> Blueprint:
    """Build the ``/api/v1/pcap`` blueprint.

    ``pcap_store`` is the :class:`PcapEvidenceStore`, ``pcap_capture_provider``
    the configured capture provider (disabled by default), and ``record_audit``
    the app's operator-audit writer. All are passed in explicitly so the
    blueprint has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("pcap", __name__)

    @bp.get("/api/v1/pcap")
    def list_pcap_evidence():
        session_id = request.args.get("session_id", "")[:128]
        if not session_id:
            return jsonify({"error": "session_id_required"}), 422
        return jsonify({
            "enabled": bool(current_app.config.get("PCAP_ENABLED")),
            "max_bytes": pcap_store.max_bytes,
            "retention_days": pcap_store.retention_days,
            "items": pcap_store.list(session_id, request.args.get("limit", 100, type=int)),
        })

    @bp.post("/api/v1/pcap")
    def upload_pcap_evidence():
        if not current_app.config.get("PCAP_ENABLED"):
            return jsonify({"error": "pcap_disabled"}), 409
        session_id = (request.form.get("session_id") or "")[:128]
        upload = request.files.get("pcap")
        if not session_id or upload is None:
            return jsonify({"error": "session_id_and_pcap_required"}), 422
        data = upload.stream.read(pcap_store.max_bytes + 1)
        try:
            metadata = pcap_store.save(session_id, data, capture_provider="operator_upload")
        except PcapValidationError as exc:
            return jsonify({"error": "pcap_validation_error", "detail": str(exc)}), 422
        record_audit(
            "pcap.upload",
            target_type="pcap",
            target_id=str(metadata.get("id") or "")[:128],
            detail={"session_id": session_id, "size_bytes": metadata.get("size_bytes")},
        )
        return jsonify(metadata), 201

    @bp.post("/api/v1/pcap/capture")
    def capture_pcap_evidence():
        if not current_app.config.get("PCAP_ENABLED"):
            return jsonify({"error": "pcap_disabled"}), 409
        payload = request.get_json(silent=True) or {}
        session_id = str(payload.get("session_id") or "")[:128]
        if not session_id:
            return jsonify({"error": "session_id_required"}), 422
        try:
            data = pcap_capture_provider.capture(session_id, pcap_store.max_bytes)
            metadata = pcap_store.save(
                session_id,
                data,
                capture_provider=str(getattr(pcap_capture_provider, "name", "custom"))[:128],
            )
        except PcapValidationError as exc:
            return jsonify({"error": "pcap_capture_unavailable", "detail": str(exc)}), 409
        record_audit(
            "pcap.capture",
            target_type="pcap",
            target_id=str(metadata.get("id") or "")[:128],
            detail={"session_id": session_id, "size_bytes": metadata.get("size_bytes")},
        )
        return jsonify(metadata), 201

    @bp.get("/api/v1/pcap/<evidence_id>/download")
    def download_pcap_evidence(evidence_id: str):
        try:
            metadata, data = pcap_store.read_verified(evidence_id)
        except PcapValidationError as exc:
            status = 404 if "not found" in str(exc) else 409
            return jsonify({"error": "pcap_unavailable", "detail": str(exc)}), status
        extension = "pcapng" if metadata.get("format") == "pcapng" else "pcap"
        record_audit(
            "pcap.download",
            target_type="pcap",
            target_id=str(metadata.get("id") or "")[:128],
            detail={
                "session_id": str(metadata.get("session_id") or "")[:128],
                "sha256": str(metadata.get("sha256") or ""),
            },
        )
        return Response(
            data,
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{metadata["id"]}.{extension}"',
                "X-Aegis-SHA256": str(metadata["sha256"]),
            },
        )

    return bp
