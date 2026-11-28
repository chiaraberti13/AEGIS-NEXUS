"""Reporting / export API routes for AEGIS-NEXUS.

Eleventh domain extracted from the ``app.py`` route monolith with the
blueprint-factory pattern (ADR 0003): case reports (JSON/Markdown/PDF/CSV), the
case evidence bundle (ZIP + manifest), the SOC summary (JSON/Markdown) and
session reports (JSON/Markdown/PDF/CSV).

Operator authentication is enforced by the app-level ``before_request`` trust
boundary (which still runs for blueprint routes). Every export is written to the
operator audit log via the injected ``record_audit``. Shareable exports pass
through ``redact_report`` with the requested redaction profile; CSV fields go
through the injected ``csv_safe`` guard (formula-injection prevention). The
provenance split is preserved — reports never invent attribution or verdicts.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable

from flask import Blueprint, Response, jsonify, request
from werkzeug.exceptions import BadRequest

from .evidence_bundle import build_evidence_bundle
from .pdf import text_to_pdf
from .redaction import REDACTION_PROFILES, redact_report
from .reporting import case_markdown, session_markdown, soc_summary_markdown
from .soc_summary import NAMED_WINDOWS, build_soc_summary


class InvalidReportProfile(BadRequest):
    """The requested export does not support the selected profile."""


def make_reports_blueprint(
    *,
    store,
    alert_store,
    detection_config,
    record_audit: Callable,
    case_operator_audit: Callable[[str], list[dict]],
    csv_safe: Callable,
) -> Blueprint:
    """Build the ``/api/v1/reports`` blueprint.

    All collaborators (``store``, ``alert_store``, ``detection_config``, the
    ``record_audit`` writer, the ``case_operator_audit`` reader and the
    ``csv_safe`` guard) are passed in explicitly so the blueprint has no
    import-time coupling to ``create_app``.
    """
    bp = Blueprint("reports", __name__)

    @bp.errorhandler(InvalidReportProfile)
    def invalid_report_profile(_exc):
        return jsonify({"error": "invalid_report_profile"}), 400

    def _report_profile(*, supports_shareable: bool = True) -> str:
        profiles = request.args.getlist("profile")
        if not profiles:
            return "internal"
        profile = profiles[0].strip().lower()
        if len(profiles) != 1 or profile not in REDACTION_PROFILES:
            raise InvalidReportProfile
        if profile == "shareable" and not supports_shareable:
            raise InvalidReportProfile
        return profile

    def _markdown_redaction_banner(report: dict, it: bool) -> str:
        note = report.get("redaction_note")
        if not note:
            return ""
        label = "Profilo di condivisione" if it else "Redaction: shareable"
        return f"> **{label}** — {note}\n\n"

    def _soc_summary_hours() -> int:
        # Named presets (24h/7d/30d) or an explicit custom `hours` window.
        named = (request.args.get("range") or "").strip().lower()
        if named in NAMED_WINDOWS:
            return NAMED_WINDOWS[named]
        return request.args.get("hours", 24, type=int)

    @bp.get("/api/v1/reports/case/<case_id>")
    def case_report(case_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "en")[:8]
        item = store.case_report(case_id[:128])
        if not item:
            return jsonify({"error": "not_found"}), 404
        item["operator_audit"] = case_operator_audit(case_id[:128])
        return jsonify(redact_report(item, profile, lang=lang)), 200

    @bp.get("/api/v1/reports/case/<case_id>.md")
    def case_report_markdown(case_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "it")[:8]
        item = store.case_report(case_id[:128])
        if not item:
            return jsonify({"error": "not_found"}), 404
        item["operator_audit"] = case_operator_audit(case_id[:128])
        item = redact_report(item, profile, lang=lang)
        body = _markdown_redaction_banner(item, lang.lower().startswith("it")) + case_markdown(item, lang)
        filename = f"aegis-{case_id[:64]}.md"
        record_audit(
            "export.case_report",
            target_type="case",
            target_id=case_id[:128],
            detail={"format": "markdown", "redaction_profile": profile},
        )
        return Response(
            body,
            content_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @bp.get("/api/v1/reports/soc-summary")
    def soc_summary_report():
        _report_profile(supports_shareable=False)
        summary = build_soc_summary(store, alert_store, detection_config, hours=_soc_summary_hours())
        return jsonify(summary)

    @bp.get("/api/v1/reports/soc-summary.md")
    def soc_summary_report_markdown():
        _report_profile(supports_shareable=False)
        summary = build_soc_summary(store, alert_store, detection_config, hours=_soc_summary_hours())
        body = soc_summary_markdown(summary, request.args.get("lang", "it")[:8])
        record_audit(
            "export.soc_summary",
            target_type="report",
            target_id="soc_summary",
            detail={"format": "markdown", "window_hours": summary["window_hours"]},
        )
        return Response(
            body,
            content_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="aegis-soc-summary.md"'},
        )

    @bp.get("/api/v1/reports/case/<case_id>.pdf")
    def case_report_pdf(case_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "it")[:8]
        item = store.case_report(case_id[:128])
        if not item:
            return jsonify({"error": "not_found"}), 404
        item["operator_audit"] = case_operator_audit(case_id[:128])
        item = redact_report(item, profile, lang=lang)
        body = _markdown_redaction_banner(item, lang.lower().startswith("it")) + case_markdown(item, lang)
        pdf = text_to_pdf(f"AEGIS-NEXUS case {case_id[:64]}", body)
        record_audit(
            "export.case_report",
            target_type="case",
            target_id=case_id[:128],
            detail={"format": "pdf", "redaction_profile": profile},
        )
        return Response(
            pdf,
            content_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aegis-{case_id[:64]}.pdf"'},
        )

    @bp.get("/api/v1/reports/case/<case_id>/bundle.zip")
    def case_evidence_bundle(case_id: str):
        _report_profile(supports_shareable=False)
        report = store.case_report(case_id[:128])
        if not report:
            return jsonify({"error": "not_found"}), 404
        report["operator_audit"] = case_operator_audit(case_id[:128])
        lang = request.args.get("lang", "it")[:8]
        markdown = case_markdown(report, lang)

        records: list[dict] = []
        for evidence in report.get("evidence", []):
            etype = str(evidence.get("evidence_type") or "evidence")
            eid = str(evidence.get("evidence_id") or "")
            if not evidence.get("available"):
                records.append({
                    "name": f"{etype}-{eid}-unavailable",
                    "record": {"evidence_type": etype, "evidence_id": eid, "available": False},
                })
                continue
            if etype == "event":
                record = store.get_event(eid) or evidence.get("summary")
            elif etype == "alert":
                record = alert_store.get(eid) or evidence.get("summary")
            else:
                record = evidence.get("summary")
            records.append({"name": f"{etype}-{eid}", "record": record})

        bundle, manifest = build_evidence_bundle(
            case_id=case_id[:128],
            report_json=report,
            report_markdown=markdown,
            evidence_records=records,
            generated_at=report["generated_at"],
        )
        record_audit(
            "export.case_bundle",
            target_type="case",
            target_id=case_id[:128],
            detail={"format": "zip", "entries": manifest["entry_count"]},
        )
        return Response(
            bundle,
            content_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="aegis-case-{case_id[:64]}-bundle.zip"'},
        )

    @bp.get("/api/v1/reports/case/<case_id>.csv")
    def case_report_csv(case_id: str):
        _report_profile(supports_shareable=False)
        item = store.case_report(case_id[:128])
        if not item:
            return jsonify({"error": "not_found"}), 404
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "case_id",
            "case_title",
            "case_status",
            "case_severity",
            "classification_provenance",
            "evidence_type",
            "evidence_id",
            "evidence_available",
            "evidence_added_at",
        ])
        for evidence in item["evidence"]:
            writer.writerow([
                csv_safe(item["case"]["id"]),
                csv_safe(item["case"]["title"]),
                csv_safe(item["case"]["status"]),
                csv_safe(item["case"]["severity"]),
                "analyst",
                csv_safe(evidence["evidence_type"]),
                csv_safe(evidence["evidence_id"]),
                csv_safe(evidence["available"]),
                csv_safe(evidence["added_at"]),
            ])
        filename = f"aegis-{case_id[:64]}.csv"
        record_audit(
            "export.case_report",
            target_type="case",
            target_id=case_id[:128],
            detail={"format": "csv"},
        )
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @bp.get("/api/v1/reports/session/<session_id>")
    def session_report(session_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "en")[:8]
        item = store.report(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        return jsonify(redact_report(item, profile, lang=lang)), 200

    @bp.get("/api/v1/reports/session/<session_id>.md")
    def session_report_markdown(session_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "it")[:8]
        item = store.report(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        item = redact_report(item, profile, lang=lang)
        body = _markdown_redaction_banner(item, lang.lower().startswith("it")) + session_markdown(item, lang)
        filename = f"aegis-{session_id[:64]}.md"
        record_audit(
            "export.session_report",
            target_type="session",
            target_id=session_id[:128],
            detail={"format": "markdown", "redaction_profile": profile},
        )
        return Response(
            body,
            content_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @bp.get("/api/v1/reports/session/<session_id>.pdf")
    def session_report_pdf(session_id: str):
        profile = _report_profile()
        lang = request.args.get("lang", "it")[:8]
        item = store.report(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        item = redact_report(item, profile, lang=lang)
        body = _markdown_redaction_banner(item, lang.lower().startswith("it")) + session_markdown(item, lang)
        pdf = text_to_pdf(f"AEGIS-NEXUS session {session_id[:64]}", body)
        record_audit(
            "export.session_report",
            target_type="session",
            target_id=session_id[:128],
            detail={"format": "pdf", "redaction_profile": profile},
        )
        return Response(
            pdf,
            content_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aegis-{session_id[:64]}.pdf"'},
        )

    @bp.get("/api/v1/reports/session/<session_id>.csv")
    def session_report_csv(session_id: str):
        _report_profile(supports_shareable=False)
        item = store.report(session_id)
        if not item:
            return jsonify({"error": "not_found"}), 404
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp",
            "collector_received_at",
            "event_id",
            "event_type",
            "severity",
            "source_ip",
            "honeypot",
            "service",
            "protocol",
            "destination_port",
            "username",
            "command",
            "payload",
            "ids_signature",
        ])
        for event in item["events"]:
            observed = event.get("observed") or {}
            credential = observed.get("credential") if isinstance(observed.get("credential"), dict) else {}
            alert = observed.get("alert") if isinstance(observed.get("alert"), dict) else {}
            writer.writerow([
                csv_safe(event.get("timestamp")),
                csv_safe(event.get("collector_received_at")),
                csv_safe(event.get("id")),
                csv_safe(event.get("event_type")),
                csv_safe(event.get("severity")),
                csv_safe(event.get("source_ip")),
                csv_safe(event.get("honeypot")),
                csv_safe(event.get("service")),
                csv_safe(event.get("protocol")),
                csv_safe(event.get("destination_port")),
                csv_safe(credential.get("username")),
                csv_safe(observed.get("command")),
                csv_safe(observed.get("payload")),
                csv_safe(alert.get("signature")),
            ])
        filename = f"aegis-{session_id[:64]}.csv"
        record_audit(
            "export.session_report",
            target_type="session",
            target_id=session_id[:128],
            detail={"format": "csv"},
        )
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return bp
