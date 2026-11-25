"""IP enrichment API routes for AEGIS-NEXUS.

Third domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003). These read-only endpoints return the
per-IP profile and its threat-intelligence view. Both validate the path IP with
the stdlib ``ipaddress`` parser (hostile input is guilty until bounded) and read
only through the store — GeoIP/ASN stay enrichment, never attacker identity, and
threat-context matches are reported with their provenance, never invented. Same
absolute URLs, behaviour unchanged; the app-level request hooks still apply.
"""

from __future__ import annotations

import ipaddress

from flask import Blueprint, jsonify


def make_ips_blueprint(*, store) -> Blueprint:
    """Build the ``/api/v1/ips`` blueprint.

    ``store`` is the composed :class:`Store`; it is passed in explicitly so the
    blueprint has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("ips", __name__)

    @bp.get("/api/v1/ips/<ip>")
    def ip_detail(ip: str):
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({"error": "invalid_ip"}), 422
        return jsonify(store.ip_profile(normalized))

    @bp.get("/api/v1/ips/<ip>/threat-intelligence")
    def ip_threat_intelligence(ip: str):
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({"error": "invalid_ip"}), 422
        return jsonify(store.threat_intelligence(normalized))

    return bp
