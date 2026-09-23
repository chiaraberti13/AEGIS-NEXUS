from __future__ import annotations

from typing import Any


def _lang_is_it(lang: str) -> bool:
    return lang.lower().startswith("it")


def explain(event: dict[str, Any], lang: str = "it") -> dict[str, Any]:
    it = _lang_is_it(lang)
    event_type = event["event_type"]
    observed = event["observed"]
    derived = event.get("derived", {})
    enrichment = event.get("enrichment", {})
    normalization = (event.get("collector") or {}).get("normalization") or {}

    labels = {
        "credential": ("Tentativo di autenticazione", "Authentication attempt"),
        "command": ("Comando osservato", "Observed command"),
        "legacy.command": ("Comando su servizio legacy", "Legacy service command"),
        "web.payload": ("Payload web osservato", "Observed web payload"),
        "web.request": ("Richiesta web osservata", "Observed web request"),
        "ids.alert": ("Alert IDS", "IDS alert"),
        "connection": ("Connessione al sensore", "Sensor connection"),
    }
    title = labels.get(event_type, ("Evento honeypot", "Honeypot event"))[0 if it else 1]

    why_parts = []
    if event_type == "credential":
        why_parts.append(
            "Un tentativo di autenticazione verso un servizio esca può evidenziare scanning, password guessing o riuso di credenziali; il singolo evento non basta però a classificare l'intento."
            if it else
            "An authentication attempt against a decoy service can expose scanning, password guessing or credential reuse; a single event is not enough to classify intent."
        )
    elif observed.get("command"):
        why_parts.append(
            "La sequenza dei comandi è spesso più informativa del singolo comando perché permette di osservare ricognizione, discovery o tentativi di staging senza eseguire il payload."
            if it else
            "Command sequences are often more informative than a single command because they can reveal reconnaissance, discovery or staging attempts without executing the payload."
        )
    elif observed.get("payload"):
        why_parts.append(
            "Il payload è un artefatto osservato direttamente e può contenere indicatori utili; va analizzato come dato ostile e mai eseguito."
            if it else
            "The payload is directly observed evidence and may contain useful indicators; it must be handled as hostile data and never executed."
        )
    elif event_type == "ids.alert":
        why_parts.append(
            "L'alert IDS è un'osservazione prodotta dal motore di detection: firma e categoria aiutano il triage, ma non provano da sole compromissione o attribuzione."
            if it else
            "The IDS alert is an observation produced by the detection engine: signature and category help triage, but do not by themselves prove compromise or attribution."
        )
    else:
        why_parts.append(
            "Proviene da un servizio esposto intenzionalmente come esca: il contesto riduce il rumore, ma non dimostra da solo identità o intenzioni della sorgente."
            if it else
            "It comes from a deliberately exposed decoy service: that context reduces noise, but does not by itself prove the source's identity or intent."
        )

    checklist = []
    if observed.get("source_ip"):
        checklist.append(
            "Correla l'IP con altre sessioni, porte, servizi e finestre temporali."
            if it else
            "Correlate the IP across sessions, ports, services and time windows."
        )
    if observed.get("credential"):
        checklist.append(
            "Confronta username, frequenza e riuso; tratta password e hash come dati sensibili."
            if it else
            "Compare usernames, frequency and reuse; treat passwords and hashes as sensitive data."
        )
    if observed.get("command") or observed.get("payload"):
        checklist.append(
            "Confronta l'artefatto con gli eventi precedenti e successivi della stessa sessione prima di formulare ipotesi."
            if it else
            "Compare the artifact with preceding and following events in the same session before forming hypotheses."
        )
    if event_type == "ids.alert":
        checklist.append(
            "Verifica signature, categoria, protocollo, porte e telemetria honeypot coincidente."
            if it else
            "Verify the signature, category, protocol, ports and coincident honeypot telemetry."
        )
    if enrichment:
        checklist.append(
            "Verifica fonte e timestamp di ogni enrichment e non confonderlo con dati osservati."
            if it else
            "Verify source and timestamp for each enrichment item and do not confuse it with observed data."
        )
    if derived.get("mitre"):
        checklist.append(
            "Controlla evidenza e razionale di ogni mapping MITRE senza trasformarlo in attribuzione."
            if it else
            "Check evidence and rationale for each MITRE mapping without turning it into attribution."
        )
    if derived.get("cve"):
        checklist.append(
            "Verifica che ogni CVE sia legata a evidenza tecnica concreta, non soltanto alla porta o al nome del servizio."
            if it else
            "Verify that every CVE is tied to concrete technical evidence, not merely to a port or service name."
        )
    if derived.get("ioc"):
        checklist.append(
            "Controlla contesto ed evidenza di ogni IOC/artefatto estratto: la presenza nel payload o comando non implica automaticamente malevolenza."
            if it else
            "Review the context and evidence for each extracted IOC/artifact: presence in a payload or command does not automatically imply maliciousness."
        )
    if normalization.get("truncated"):
        checklist.append(
            "Il collector ha troncato almeno un campo o una collezione: verifica i percorsi in collector.normalization prima di considerare completo l'artefatto o l'estrazione IOC."
            if it else
            "The collector truncated at least one field or collection: review collector.normalization paths before treating the artifact or IOC extraction as complete."
        )
    if normalization.get("lossy") and not normalization.get("truncated"):
        checklist.append(
            "La normalizzazione ha modificato il contenuto ricevuto: verifica chiavi scartate o coercizioni dichiarate dal collector."
            if it else
            "Normalization modified received content: review collector-disclosed dropped keys or coercions."
        )
    if not checklist:
        checklist.append(
            "Esamina gli eventi vicini nella stessa sessione prima di formulare ipotesi."
            if it else
            "Inspect neighboring events in the same session before forming hypotheses."
        )

    questions = [
        (
            "Questo comportamento si ripete sulla stessa sorgente o su sorgenti diverse?"
            if it else
            "Does this behavior repeat from the same source or from different sources?"
        ),
        (
            "Esiste una progressione temporale tra connessione, credenziali, comandi, payload o alert IDS?"
            if it else
            "Is there a temporal progression across connection, credentials, commands, payloads or IDS alerts?"
        ),
        (
            "Quali elementi sono osservati direttamente e quali provengono da enrichment o analisi derivata?"
            if it else
            "Which elements were directly observed and which came from enrichment or derived analysis?"
        ),
    ]

    limitations = [
        (
            "Il singolo evento non dimostra identità, intenzione o attribuzione."
            if it else
            "A single event does not prove identity, intent or attribution."
        )
    ]
    if normalization.get("truncated"):
        limitations.append(
            "Una parte dell'evidenza memorizzata è troncata per limiti di sicurezza/risorsa; le analisi derivate da quei campi possono essere incomplete."
            if it else
            "Part of the stored evidence is truncated by security/resource bounds; analysis derived from those fields may be incomplete."
        )
    if normalization.get("redacted"):
        limitations.append(
            "I segreti delle credenziali sono redatti per policy; fingerprint e lunghezza descrivono il valore originale ricevuto."
            if it else
            "Credential secrets are policy-redacted; fingerprint and length describe the original submitted value."
        )

    return {
        "title": title,
        "why_interesting": " ".join(why_parts),
        "soc_checklist": checklist,
        "questions": questions,
        "provenance": ["observed", "enrichment", "derived", "hypotheses", "collector"],
        "limitations": limitations,
    }


def explain_session(bundle: dict[str, Any], lang: str = "it") -> dict[str, Any]:
    it = _lang_is_it(lang)
    session = bundle.get("session", {})
    summary = bundle.get("summary", {})
    events = bundle.get("events", [])
    analysis = bundle.get("analysis", {})
    truncated = bool(analysis.get("truncated"))
    correlation = summary.get("correlation") or {}
    normalized_lossy = [
        event for event in events
        if ((event.get("collector") or {}).get("normalization") or {}).get("lossy")
    ]
    normalized_truncated = [
        event for event in events
        if ((event.get("collector") or {}).get("normalization") or {}).get("truncated")
    ]

    facts = []
    event_count = int(summary.get("event_count") or len(events))
    if truncated:
        facts.append(
            f"L'analisi è limitata agli ultimi {event_count} eventi conservati restituiti per questa sessione."
            if it else
            f"Analysis is limited to the latest {event_count} retained events returned for this session."
        )
    else:
        facts.append(
            f"La sessione contiene {event_count} eventi osservati."
            if it else
            f"The session contains {event_count} observed events."
        )
    if session.get("source_ip"):
        facts.append(
            f"Sorgente osservata: {session['source_ip']}."
            if it else
            f"Observed source: {session['source_ip']}."
        )
    if session.get("service"):
        facts.append(
            f"Servizio: {session['service']} su {session.get('protocol', 'unknown')}/{session.get('destination_port', 0)}."
            if it else
            f"Service: {session['service']} on {session.get('protocol', 'unknown')}/{session.get('destination_port', 0)}."
        )
    if normalized_lossy:
        facts.append(
            f"{len(normalized_lossy)} eventi contengono trasformazioni lossy dichiarate dal collector; {len(normalized_truncated)} includono troncamenti."
            if it else
            f"{len(normalized_lossy)} events contain collector-disclosed lossy transformations; {len(normalized_truncated)} include truncation."
        )

    focus = []
    if summary.get("credentials"):
        focus.append(
            f"{summary['credentials']} eventi contengono tentativi di credenziali: confronta username, riuso e sequenza temporale."
            if it else
            f"{summary['credentials']} events contain credential attempts: compare usernames, reuse and temporal sequence."
        )
    if summary.get("commands"):
        focus.append(
            f"{summary['commands']} eventi contengono comandi: analizza l'ordine e l'obiettivo apparente senza eseguirli."
            if it else
            f"{summary['commands']} events contain commands: analyze their order and apparent objective without executing them."
        )
    if summary.get("payloads"):
        focus.append(
            f"{summary['payloads']} eventi contengono payload: estrai indicatori in modo statico e mantieni l'artefatto isolato."
            if it else
            f"{summary['payloads']} events contain payloads: extract indicators statically and keep the artifact isolated."
        )
    if summary.get("ids_alerts"):
        focus.append(
            f"{summary['ids_alerts']} alert IDS sono presenti: confrontali con la telemetria osservata nella stessa finestra."
            if it else
            f"{summary['ids_alerts']} IDS alerts are present: compare them with observed telemetry in the same window."
        )
    if summary.get("mitre"):
        focus.append(
            "Sono presenti mapping MITRE evidence-backed: verifica individualmente razionale ed evidenza."
            if it else
            "Evidence-backed MITRE mappings are present: verify each rationale and evidence item individually."
        )
    if summary.get("cves"):
        focus.append(
            "Sono presenti correlazioni CVE evidence-backed: verifica che l'evidenza sia specifica della vulnerabilità."
            if it else
            "Evidence-backed CVE correlations are present: verify that the evidence is specific to the vulnerability."
        )
    if summary.get("iocs"):
        focus.append(
            f"Sono presenti {summary['iocs']} IOC/artefatti derivati: correlali tra sessioni senza considerarli automaticamente indicatori malevoli."
            if it else
            f"{summary['iocs']} derived IOCs/artifacts are present: correlate them across sessions without automatically treating them as malicious indicators."
        )
    if not focus:
        focus.append(
            "La sessione contiene soprattutto telemetria di connessione: osserva frequenza, porte e ricorrenza prima di classificare il comportamento."
            if it else
            "The session mainly contains connection telemetry: inspect frequency, ports and recurrence before classifying behavior."
        )

    next_steps = [
        (
            "Ricostruisci la timeline completa e individua i passaggi che cambiano il livello di evidenza."
            if it else
            "Reconstruct the complete timeline and identify transitions that change the evidence level."
        ),
        (
            "Confronta la sorgente con altre sessioni e verifica eventuale riuso di username, comandi, payload o IOC."
            if it else
            "Compare the source with other sessions and check for reuse of usernames, commands, payloads or IOCs."
        ),
        (
            "Controlla enrichment esterni separatamente e annota fonte, timestamp e possibili limiti."
            if it else
            "Review external enrichment separately and record source, timestamp and possible limitations."
        ),
        (
            "Mantieni distinte osservazioni, enrichment, dati derivati, ipotesi e metadata controllati dal collector nel report finale."
            if it else
            "Keep observations, enrichment, derived data, hypotheses and collector-controlled metadata separate in the final report."
        ),
    ]

    return {
        "title": "Analisi guidata della sessione" if it else "Guided session analysis",
        "facts": facts,
        "focus": focus,
        "next_steps": next_steps,
        "limitations": [
            *([
                (
                    "La sessione supera il limite di analisi configurato: timeline, grafo, report e Study Mode usano soltanto il sottoinsieme più recente indicato."
                    if it else
                    "The session exceeds the configured analysis limit: timeline, graph, report and Study Mode use only the indicated latest subset."
                )
            ] if truncated else []),
            *([
                (
                    "Uno o più eventi hanno evidenza troncata dal collector: comandi, payload o IOC derivati da quei campi possono essere incompleti."
                    if it else
                    "One or more events contain collector-truncated evidence: commands, payloads or IOCs derived from those fields may be incomplete."
                )
            ] if normalized_truncated else []),
            (
                (
                    "La correlazione della sessione è euristica e usa identità tecnica più finestra temporale; eventi distinti possono essere aggregati o una singola attività può essere separata."
                    if it else
                    "Session correlation is heuristic and uses technical identity plus a time window; distinct activity may be grouped or one activity may be split."
                )
                if correlation.get("strength") == "heuristic"
                else (
                    "La correlazione usa un identificatore esplicito di connessione/flow, ma questo non dimostra l'identità della persona dietro gli eventi."
                    if it else
                    "Correlation uses an explicit connection/flow identifier, but this does not prove the identity of the person behind the events."
                )
            ),
            (
                "Geolocalizzazione, ASN e reputazione IP descrivono infrastruttura, non identità umana."
                if it else
                "Geolocation, ASN and IP reputation describe infrastructure, not human identity."
            ),
        ],
    }
