"""Analytics read API routes for AEGIS-NEXUS.

Ninth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the read-only analytical views — filter
options, the main dashboard rollup, the geospatial attack map, the session
relationship graph and the correlation workspace.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). These endpoints are strictly
read/aggregate: they keep the evidence-first provenance split intact (GeoIP/ASN
stays enrichment, correlation stays a heuristic-tagged derived conclusion) and
never re-derive or attribute. The ``filters_from_request`` helper is injected to
avoid importing ``app`` (no import cycle).
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, jsonify, request


def make_analytics_blueprint(
    *,
    store,
    correlation_workspace,
    filters_from_request: Callable[[], dict[str, str]],
) -> Blueprint:
    """Build the analytics-read blueprint.

    ``store`` is the composed :class:`Store`; ``correlation_workspace`` is the
    :class:`CorrelationWorkspace`; ``filters_from_request`` is the app's request
    filter helper. All are passed in explicitly so the blueprint has no
    import-time coupling to ``create_app``.
    """
    bp = Blueprint("analytics", __name__)

    @bp.get("/api/v1/meta/filters")
    def filter_options():
        return jsonify(store.filter_options(request.args.get("hours", 720, type=int)))

    @bp.get("/api/v1/dashboard")
    def dashboard():
        hours = request.args.get("hours", 24, type=int)
        q = request.args.get("q", type=str)
        include_sim = request.args.get("include_simulation", "false").lower() in {"1", "true", "yes"}
        return jsonify(
            store.dashboard(
                hours=hours,
                include_simulation=include_sim,
                q=q,
                filters=filters_from_request(),
            )
        )

    @bp.get("/api/v1/geo/attacks")
    def geo_attacks():
        hours = request.args.get("hours", 24, type=int)
        return jsonify(store.geo_attacks(hours=hours, filters=filters_from_request()))

    @bp.get("/api/v1/relations")
    def relations():
        return jsonify(store.relations(request.args.get("session_id", "")[:128]))

    @bp.get("/api/v1/correlations")
    def correlations():
        session_id = request.args.get("session_id", "")[:128]
        if not session_id:
            return jsonify({"error": "session_id_required"}), 422
        item = correlation_workspace.analyze(
            session_id,
            hours=request.args.get("hours", 720, type=int),
            limit=request.args.get("limit", 50, type=int),
            min_score=request.args.get("min_score", 0.50, type=float),
        )
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    return bp
