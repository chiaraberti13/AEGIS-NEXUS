"""Detection API routes for AEGIS-NEXUS.

First domain extracted from the ``app.py`` route monolith using the
blueprint-factory pattern (ADR 0003): a module-level factory captures the
dependencies it needs and returns a Flask ``Blueprint`` with the same absolute
URLs, so the public API and behaviour are unchanged. The app-level
``before_request`` trust-boundary enforcement and ``after_request`` security
headers still apply to these routes, because Flask runs app-wide request hooks
for blueprint routes too.

These endpoints are read-only and expose only non-sensitive detection posture
(the public rule view, MITRE ATT&CK coverage and detection statistics); they
derive nothing and never echo attacker-controlled content.

See the Flask blueprint docs: https://flask.palletsprojects.com/en/stable/blueprints/
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from .detection_coverage import mitre_coverage


def make_detections_blueprint(*, detection_config, alert_store) -> Blueprint:
    """Build the ``/api/v1/detections`` blueprint.

    ``detection_config`` is the loaded :class:`DetectionConfig`; ``alert_store``
    is the :class:`AlertStore` used for detection statistics. Both are passed in
    explicitly so the blueprint has no import-time coupling to ``create_app``.
    """
    bp = Blueprint("detections", __name__)

    @bp.get("/api/v1/detections/config")
    def detection_config_status():
        return jsonify(detection_config.public())

    @bp.get("/api/v1/detections/coverage")
    def detection_coverage_view():
        return jsonify(mitre_coverage(detection_config))

    @bp.get("/api/v1/detections/stats")
    def detection_statistics():
        return jsonify(alert_store.statistics())

    return bp
