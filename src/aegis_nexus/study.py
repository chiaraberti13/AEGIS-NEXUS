from __future__ import annotations

from typing import Any


def explain(event: dict[str, Any], lang: str = "it") -> dict[str, Any]:
    it = lang.lower().startswith("it")
    event_type = event["event_type"]
    observed = event["observed"]
    labels = {
        "credential": ("Tentativo di autenticazione", "Authentication attempt"),
        "command": ("Comando osservato", "Observed command"),
        "ids.alert": ("Alert IDS", "IDS alert"),
        "connection": ("Connessione al sensore", "Sensor connection"),
    }
    title = labels.get(event_type, ("Evento honeypot", "Honeypot event"))[0 if it else 1]
    why = (
        "È interessante perché proviene da un servizio esposto intenzionalmente come esca: il contesto riduce il rumore, ma non dimostra da solo identità o intenzioni dell'origine."
        if it else
        "It is interesting because it comes from a deliberately exposed decoy service: that context reduces noise, but does not by itself prove the source's identity or intent."
    )
    observe = []
    if observed.get("source_ip"):
        observe.append("Correla l'IP con altre sessioni e finestre temporali." if it else "Correlate the IP across sessions and time windows.")
    if observed.get("credential"):
        observe.append("Confronta username, frequenza e riuso; tratta le password come dati sensibili." if it else "Compare usernames, frequency and reuse; treat passwords as sensitive data.")
    if observed.get("command") or observed.get("payload"):
        observe.append("Analizza sequenza, obiettivo apparente e indicatori derivabili dal payload senza eseguirlo." if it else "Analyze sequence, apparent objective and payload-derived indicators without executing it.")
    if event.get("enrichment"):
        observe.append("Mantieni l'enrichment separato dall'osservazione grezza e verifica fonte e timestamp." if it else "Keep enrichment separate from raw observation and verify source and timestamp.")
    if event.get("derived", {}).get("mitre"):
        observe.append("Verifica che ogni mapping MITRE abbia razionale ed evidenza, senza trasformarlo in attribuzione." if it else "Verify that every MITRE mapping has rationale and evidence, without turning it into attribution.")
    if not observe:
        observe.append("Cerca eventi vicini nella stessa sessione prima di formulare ipotesi." if it else "Inspect neighboring events in the same session before forming hypotheses.")
    return {"title": title, "why_interesting": why, "soc_checklist": observe, "provenance": ["observed", "enrichment", "derived", "hypotheses"]}
