from __future__ import annotations

import html
import json
import re
from typing import Any

MAX_MARKDOWN_EVENTS = 200
_MARKDOWN_META = re.compile(r"([\\`*_{}\[\]#+!|])")


def _it(lang: str) -> bool:
    return str(lang or "").lower().startswith("it")


def _inline(value: Any) -> str:
    if value in (None, ""):
        return "—"
    text = html.escape(str(value), quote=False)
    return _MARKDOWN_META.sub(r"\\\1", text)


def _code(value: Any) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)
    else:
        text = str(value if value not in (None, "") else "—")
    text = html.escape(text.replace("\r\n", "\n").replace("\r", "\n"), quote=False)
    return "\n".join("    " + line for line in text.split("\n"))


def _bullet(label: str, value: Any) -> str:
    return f"- **{label}:** {_inline(value)}"


def session_markdown(report: dict[str, Any], lang: str = "it") -> str:
    it = _it(lang)
    session = report.get("session") or {}
    summary = report.get("summary") or {}
    facts = report.get("facts") or {}
    lines: list[str] = [
        "# AEGIS-NEXUS — " + ("Report investigativo di sessione" if it else "Session investigation report"),
        "",
        _bullet("Generato" if it else "Generated", report.get("generated_at")),
        _bullet("Tipo report" if it else "Report type", report.get("report_type")),
        "",
        "> " + (
            "Il documento mantiene separate osservazioni, enrichment esterni e analisi derivate. Non costituisce attribuzione."
            if it else
            "This document keeps observations, external enrichment and derived analysis separate. It is not an attribution statement."
        ),
        "",
        "## " + ("Fatti della sessione" if it else "Session facts"),
        "",
        _bullet("Session ID", session.get("id")),
        _bullet("IP sorgente" if it else "Source IP", session.get("source_ip")),
        _bullet("Honeypot", session.get("honeypot")),
        _bullet("Servizio" if it else "Service", session.get("service")),
        _bullet("Protocollo" if it else "Protocol", session.get("protocol")),
        _bullet("Porta destinazione" if it else "Destination port", session.get("destination_port")),
        _bullet("Inizio" if it else "Started", session.get("started_at")),
        _bullet("Ultima osservazione" if it else "Last seen", session.get("last_seen")),
        _bullet("Metodo correlazione" if it else "Correlation method", summary.get("correlation_method")),
        _bullet("Eventi" if it else "Events", facts.get("event_count")),
        _bullet("Primo timestamp sensore" if it else "First sensor timestamp", facts.get("sensor_first_timestamp")),
        _bullet("Ultimo timestamp sensore" if it else "Last sensor timestamp", facts.get("sensor_last_timestamp")),
        _bullet("Prima ricezione collector" if it else "Collector first received", facts.get("collector_first_received")),
        _bullet("Ultima ricezione collector" if it else "Collector last received", facts.get("collector_last_received")),
        "",
        "## " + ("Credenziali osservate" if it else "Observed credentials"),
        "",
    ]

    credentials = report.get("credentials") or []
    if credentials:
        for item in credentials:
            lines.extend([
                _bullet("Event ID", item.get("event_id")),
                _bullet("Username", item.get("username")),
                _bullet("Lunghezza ricevuta dal collector" if it else "Collector-received length", item.get("password_length")),
                _bullet("SHA-256 ricevuto dal collector" if it else "Collector-received SHA-256", item.get("password_sha256")),
                _bullet("Cattura completa" if it else "Complete capture", item.get("password_complete")),
                *([
                    _bullet("Lunghezza originale dichiarata dal sensore" if it else "Sensor-reported original length", item.get("sensor_reported_password_length")),
                    _bullet("SHA-256 originale dichiarato dal sensore" if it else "Sensor-reported original SHA-256", item.get("sensor_reported_password_sha256")),
                ] if item.get("password_complete") is False else []),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessuna credenziale osservata." if it else "No credentials observed."), ""])

    lines.extend(["## " + ("Comandi osservati" if it else "Observed commands"), ""])
    commands = report.get("commands") or []
    if commands:
        for item in commands:
            lines.extend([_bullet("Event ID", item.get("event_id")), "", _code(item.get("command")), ""])
    else:
        lines.extend(["- " + ("Nessun comando osservato." if it else "No commands observed."), ""])

    lines.extend(["## " + ("Payload osservati" if it else "Observed payloads"), ""])
    payloads = report.get("payloads") or []
    if payloads:
        for item in payloads:
            lines.extend([_bullet("Event ID", item.get("event_id")), "", _code(item.get("payload")), ""])
    else:
        lines.extend(["- " + ("Nessun payload osservato." if it else "No payloads observed."), ""])

    lines.extend(["## " + ("Enrichment esterno" if it else "External enrichment"), ""])
    enrichments = report.get("enrichment") or []
    if enrichments:
        for item in enrichments:
            lines.extend([_bullet("Event ID", item.get("event_id"))])
            sources = item.get("sources") if isinstance(item.get("sources"), dict) else {}
            for kind, source in sources.items():
                if not isinstance(source, dict):
                    continue
                lines.extend([
                    _bullet("Tipo" if it else "Kind", kind),
                    _bullet("Fonte" if it else "Source", source.get("source")),
                    _bullet("Osservato il" if it else "Observed at", source.get("observed_at")),
                    "",
                    _code(source.get("data")),
                    "",
                ])
    else:
        lines.extend(["- " + ("Nessun enrichment esterno." if it else "No external enrichment."), ""])

    lines.extend(["## IOC / " + ("artefatti derivati" if it else "derived artifacts"), ""])
    iocs = report.get("derived_iocs") or []
    if iocs:
        for entry in iocs:
            ioc = entry.get("ioc") if isinstance(entry.get("ioc"), dict) else {}
            lines.extend([
                _bullet("Event ID", entry.get("event_id")),
                _bullet("Tipo" if it else "Type", ioc.get("type")),
                _bullet("Valore" if it else "Value", ioc.get("value")),
                _bullet("Classificazione" if it else "Classification", ioc.get("classification")),
                _bullet("Evidenza" if it else "Evidence", ", ".join(map(str, ioc.get("evidence") or []))),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessun IOC/artefatto derivato." if it else "No derived IOC/artifact."), ""])

    lines.extend(["## " + ("Mapping supportati da evidenza" if it else "Evidence-backed mappings"), ""])
    mappings = report.get("evidence_backed_mappings") or []
    if mappings:
        for entry in mappings:
            mapping = entry.get("mapping") if isinstance(entry.get("mapping"), dict) else {}
            identifier = mapping.get("technique_id") or mapping.get("cve_id") or "—"
            lines.extend([
                _bullet("Event ID", entry.get("event_id")),
                _bullet("Famiglia" if it else "Family", entry.get("family")),
                _bullet("ID", identifier),
                _bullet("Razionale" if it else "Rationale", mapping.get("rationale")),
                _bullet("Evidenza" if it else "Evidence", ", ".join(map(str, mapping.get("evidence") or []))),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessun mapping MITRE/CVE evidence-backed." if it else "No evidence-backed MITRE/CVE mappings."), ""])

    events = report.get("events") or []
    lines.extend(["## " + ("Appendice eventi" if it else "Event appendix"), ""])
    for event in events[:MAX_MARKDOWN_EVENTS]:
        lines.extend([
            f"### {_inline(event.get('timestamp'))} — {_inline(event.get('event_type'))}",
            "",
            _bullet("Event ID", event.get("id")),
            _bullet("Ricevuto dal collector" if it else "Collector received", event.get("collector_received_at")),
            _bullet("Severità" if it else "Severity", event.get("severity")),
            _bullet("IP sorgente" if it else "Source IP", event.get("source_ip")),
            "",
            "#### " + ("OSSERVATO" if it else "OBSERVED"),
            "",
            _code(event.get("observed") or {}),
            "",
        ])
        collector = event.get("collector") if isinstance(event.get("collector"), dict) else {}
        if collector:
            lines.extend([
                "#### " + ("METADATI COLLECTOR" if it else "COLLECTOR METADATA"),
                "",
                _code(collector),
                "",
            ])
        if event.get("enrichment"):
            lines.extend(["#### " + ("ENRICHMENT ESTERNO" if it else "EXTERNAL ENRICHMENT"), "", _code(event["enrichment"]), ""])
        if event.get("derived"):
            lines.extend(["#### " + ("DERIVATO" if it else "DERIVED"), "", _code(event["derived"]), ""])
        if event.get("hypotheses"):
            lines.extend(["#### " + ("IPOTESI" if it else "HYPOTHESES"), "", _code(event["hypotheses"]), ""])

    if len(events) > MAX_MARKDOWN_EVENTS:
        lines.extend([
            "> " + (
                f"Appendice limitata ai primi {MAX_MARKDOWN_EVENTS} eventi su {len(events)} per contenere la dimensione del file."
                if it else
                f"Appendix limited to the first {MAX_MARKDOWN_EVENTS} of {len(events)} events to bound file size."
            ),
            "",
        ])

    lines.extend(["## " + ("Limiti analitici" if it else "Analytical limitations"), ""])
    for limitation in report.get("limitations") or []:
        lines.append("- " + _inline(limitation))
    lines.append("")
    return "\n".join(lines)


def case_markdown(report: dict[str, Any], lang: str = "it") -> str:
    it = _it(lang)
    case = report.get("case") or {}
    stats = report.get("statistics") or {}
    lines: list[str] = [
        "# AEGIS-NEXUS — " + ("Report del caso" if it else "Case report"),
        "",
        _bullet("Generato" if it else "Generated", report.get("generated_at")),
        _bullet("Case ID", case.get("id")),
        "",
        "> " + (
            "Stato, severità, sintesi, tag e note sono classificazioni o annotazioni dell’analista, non telemetria osservata."
            if it else
            "Status, severity, summary, tags and notes are analyst classifications or annotations, not observed telemetry."
        ),
        "",
        "## " + ("Classificazione analista" if it else "Analyst classification"),
        "",
        _bullet("Titolo" if it else "Title", case.get("title")),
        _bullet("Stato" if it else "Status", case.get("status")),
        _bullet("Severità" if it else "Severity", case.get("severity")),
        _bullet("Tag", ", ".join(map(str, case.get("tags") or []))),
        _bullet("Creato" if it else "Created", case.get("created_at")),
        _bullet("Aggiornato" if it else "Updated", case.get("updated_at")),
        _bullet("Chiuso" if it else "Closed", case.get("closed_at")),
        _bullet("Provenienza classificazione" if it else "Classification provenance", case.get("classification_provenance")),
        "",
        "### " + ("Sintesi investigativa" if it else "Investigation summary"),
        "",
        _code(case.get("summary")),
        "",
        "## " + ("Riferimenti di evidenza" if it else "Evidence references"),
        "",
    ]

    evidence = report.get("evidence") or []
    if evidence:
        for item in evidence:
            lines.extend([
                _bullet("Tipo" if it else "Type", item.get("evidence_type")),
                _bullet("ID", item.get("evidence_id")),
                _bullet("Disponibile" if it else "Available", item.get("available")),
                _bullet("Aggiunto il" if it else "Added at", item.get("added_at")),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessun riferimento di evidenza." if it else "No evidence references."), ""])

    lines.extend([
        "## " + ("Note analista" if it else "Analyst notes"),
        "",
    ])
    notes = report.get("notes") or []
    if notes:
        for note in notes:
            lines.extend([
                _bullet("Creato" if it else "Created", note.get("created_at")),
                _bullet("Provenienza" if it else "Provenance", note.get("provenance")),
                "",
                _code(note.get("body")),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessuna nota analista." if it else "No analyst notes."), ""])

    lines.extend(["## " + ("Audit trail" if it else "Audit trail"), ""])
    history = report.get("history") or []
    if history:
        for entry in history:
            lines.extend([
                _bullet("Timestamp", entry.get("timestamp")),
                _bullet("Azione" if it else "Action", entry.get("action")),
                "",
                _code(entry.get("detail") or {}),
                "",
            ])
    else:
        lines.extend(["- " + ("Nessuna voce di audit." if it else "No audit entries."), ""])

    lines.extend([
        "## " + ("Statistiche caso" if it else "Case statistics"),
        "",
        _bullet("Riferimenti evidenza" if it else "Evidence references", stats.get("evidence_references")),
        _bullet("Riferimenti disponibili" if it else "Available references", stats.get("available_references")),
        _bullet("Riferimenti non disponibili" if it else "Unavailable references", stats.get("unavailable_references")),
        _bullet("Note", stats.get("notes")),
        "",
        "## " + ("Limiti analitici" if it else "Analytical limitations"),
        "",
    ])
    for limitation in report.get("limitations") or []:
        lines.append("- " + _inline(limitation))
    lines.append("")
    return "\n".join(lines)
