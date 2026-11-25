"""Enrichment/CTI provider status API routes for AEGIS-NEXUS.

Second domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003). These read-only endpoints report the
configuration/status of the external-context providers — the GeoIP/ASN
enricher, the benign-scanner context and the threat-context (CTI) provider —
without exposing secrets or making network requests. Same absolute URLs,
behaviour unchanged; the app-level request hooks still apply.
"""

from __future__ import annotations

from flask import Blueprint, jsonify

_UNKNOWN_PROVIDER_STATUS = {
    "mode": "custom",
    "configured": True,
    "network_requests": None,
}


def make_status_blueprint(*, enricher, benign_scanners, threat_context) -> Blueprint:
    """Build the provider-status blueprint.

    ``enricher`` and ``threat_context`` are the configured providers (either may
    expose a ``status()`` callable); ``benign_scanners`` is the
    :class:`BenignScannerContext`. All are passed in explicitly so the blueprint
    has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("providers_status", __name__)

    @bp.get("/api/v1/enrichment/status")
    def enrichment_status():
        status = getattr(enricher, "status", None)
        return jsonify(status() if callable(status) else dict(_UNKNOWN_PROVIDER_STATUS))

    @bp.get("/api/v1/benign-scanners/status")
    def benign_scanner_status():
        return jsonify(benign_scanners.status())

    @bp.get("/api/v1/threat-context/status")
    def threat_context_status():
        status = getattr(threat_context, "status", None)
        return jsonify(status() if callable(status) else dict(_UNKNOWN_PROVIDER_STATUS))

    return bp
