"""Event/session read API routes for AEGIS-NEXUS.

Fourth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the read-only activity feed — paginated
event and session listings and the single-event / single-session fetches. The
POST ``/api/v1/events`` ingest path is deliberately NOT here: it stays in the
authenticated write/ingest core.

Pagination helpers (`filters_from_request`, `pagination_scope`) are passed in as
callables rather than imported, so this module never imports ``app`` (no import
cycle). Same absolute URLs, behaviour unchanged; the app-level request hooks
still apply. Bad pagination cursors fail closed with 422.
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, jsonify, request

from .pagination import CursorError


def make_activity_blueprint(
    *,
    store,
    filters_from_request: Callable[[], dict[str, str]],
    pagination_scope: Callable[..., str],
) -> Blueprint:
    """Build the activity (events + sessions read) blueprint.

    ``store`` is the composed :class:`Store`; ``filters_from_request`` and
    ``pagination_scope`` are the app's request helpers, passed in explicitly to
    avoid any import-time coupling to ``create_app``.
    """
    bp = Blueprint("activity", __name__)

    @bp.get("/api/v1/events")
    def events():
        limit = request.args.get("limit", 100, type=int)
        q = request.args.get("q", type=str)
        filters = filters_from_request()
        hours = request.args.get("hours", type=int)
        if hours is not None:
            hours = max(1, min(hours, 720))
        scope = pagination_scope("events", q=q, filters=filters, hours=hours)
        try:
            page = store.page_events(
                limit=limit,
                q=q,
                filters=filters,
                hours=hours,
                cursor=request.args.get("cursor", type=str),
                scope=scope,
            )
        except CursorError:
            return jsonify({"error": "invalid_cursor"}), 422
        return jsonify(page)

    @bp.get("/api/v1/events/<event_id>")
    def event_detail(event_id: str):
        item = store.get_event(event_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    @bp.get("/api/v1/sessions")
    def sessions():
        limit = request.args.get("limit", 100, type=int)
        q = request.args.get("q", type=str)
        scope = pagination_scope("sessions", q=q)
        try:
            page = store.page_sessions(
                limit=limit,
                q=q,
                cursor=request.args.get("cursor", type=str),
                scope=scope,
            )
        except CursorError:
            return jsonify({"error": "invalid_cursor"}), 422
        return jsonify(page)

    @bp.get("/api/v1/sessions/<session_id>")
    def session_detail(session_id: str):
        item = store.get_session(session_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    return bp
