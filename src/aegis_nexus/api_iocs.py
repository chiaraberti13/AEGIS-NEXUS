"""IOC workspace API routes for AEGIS-NEXUS.

Sixth domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): the IOC list, the CSV export and the
single-IOC detail view.

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). The CSV export runs every
field through the injected ``csv_safe`` helper (formula-injection prevention)
and is written to the operator audit log via ``record_audit``. IOCs stay a
correlation container with provenance/classification, never a verdict.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable

from flask import Blueprint, Response, jsonify, request


def make_iocs_blueprint(*, ioc_workspace, csv_safe: Callable, record_audit: Callable) -> Blueprint:
    """Build the ``/api/v1/iocs`` blueprint.

    ``ioc_workspace`` is the :class:`IOCWorkspace`; ``csv_safe`` is the app's
    CSV formula-injection guard and ``record_audit`` its operator-audit writer.
    All are passed in explicitly so the blueprint has no import-time coupling to
    ``create_app``.
    """
    bp = Blueprint("iocs", __name__)

    @bp.get("/api/v1/iocs")
    def iocs():
        return jsonify(ioc_workspace.list(
            limit=request.args.get("limit", 200, type=int),
            q=request.args.get("q", type=str),
            ioc_type=request.args.get("type", type=str),
            hours=request.args.get("hours", 720, type=int),
        ))

    @bp.get("/api/v1/iocs/export.csv")
    def export_iocs_csv():
        data = ioc_workspace.list(
            limit=500,
            q=request.args.get("q", type=str),
            ioc_type=request.args.get("type", type=str),
            hours=request.args.get("hours", 720, type=int),
        )
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "type", "value", "first_seen", "last_seen", "occurrences",
            "source_ips", "session_ids", "honeypots", "services", "provenance", "classification",
        ])
        for item in data["items"]:
            writer.writerow([
                csv_safe(item.get("id")),
                csv_safe(item.get("type")),
                csv_safe(item.get("value")),
                csv_safe(item.get("first_seen")),
                csv_safe(item.get("last_seen")),
                item.get("occurrences", 0),
                csv_safe(";".join(item.get("source_ips") or [])),
                csv_safe(";".join(item.get("session_ids") or [])),
                csv_safe(";".join(item.get("honeypots") or [])),
                csv_safe(";".join(item.get("services") or [])),
                csv_safe(item.get("provenance")),
                csv_safe(item.get("classification")),
            ])
        record_audit(
            "export.ioc_csv",
            target_type="ioc",
            detail={"format": "csv", "rows": len(data["items"])},
        )
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="aegis-iocs.csv"'},
        )

    @bp.get("/api/v1/iocs/<item_id>")
    def ioc_detail(item_id: str):
        item = ioc_workspace.get(
            item_id[:128],
            hours=request.args.get("hours", 720, type=int),
        )
        return (jsonify(item), 200) if item else (jsonify({"error": "not_found"}), 404)

    return bp
