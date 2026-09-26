# Behavioral Analytics / Analisi comportamentale

## English

AEGIS behavioral analytics are deterministic, evidence-backed measurements over stored telemetry. They are not ML classifications, reputation scores, threat-actor attribution, or statements of maliciousness.

### Baseline contract

For an anchor event, AEGIS reads a bounded historical context ending at the event timestamp and explicitly excludes the anchor event itself. This makes live analysis, historical analysis and future replay deterministic.

The framework exposes three windows:

- **24h**
- **7d**
- **30d**

Each window reports its start/end, historical sample count, minimum required samples, readiness, distinct-value counts and a bounded preview of baseline values. The preview may be truncated for response size; novelty evaluation uses the complete bounded history rather than the preview.

The default cold-start threshold is 20 historical events and can be changed with \`AEGIS_ANALYTICS_MIN_SAMPLES\`. A window is not ready below the threshold. If the 30-day history hits the configured analytics event limit and is therefore truncated, anomaly-like findings are suppressed rather than evaluated against incomplete history.

### Initial novelty analytics

Once the 30-day baseline is ready, AEGIS can report values not observed in that baseline for:

- source IP;
- country;
- ASN;
- username;
- SHA-256 of an observed payload;
- exact URL/domain artifacts already deterministically extracted into \`derived.ioc\`.

Every finding is classified as \`derived_analytic\`, carries \`attribution: false\`, identifies the concrete anchor event, includes the measured value and baseline sample count, and explains that novelty does not mean maliciousness.

The payload SHA-256 used by analytics is a deterministic fingerprint of the stored observed payload. It is not automatically promoted to Threat Intelligence or reputation.

### API drill-down

\`GET /api/v1/analytics/events/<event_id>\` returns the three baseline windows, cold-start/truncation policy, historical scope and findings for that event.

No finding is written into \`observed\`, and analytics never rewrite the source event.

---

## Italiano

Le analisi comportamentali di AEGIS sono misure deterministiche e supportate da evidenza sulla telemetria memorizzata. Non sono classificazioni ML, reputation score, attribuzione a threat actor o affermazioni di maliciousness.

### Contratto delle baseline

Per un evento anchor, AEGIS legge uno storico bounded che termina al timestamp dell'evento ed esclude esplicitamente l'evento anchor. In questo modo analisi live, analisi storiche e futuri replay restano deterministici.

Il framework espone tre finestre:

- **24h**
- **7d**
- **30d**

Ogni finestra riporta inizio/fine, numero di campioni storici, minimo richiesto, readiness, conteggi dei valori distinti e una preview bounded dei valori della baseline. La preview può essere troncata per limitare la risposta; la valutazione della novità usa invece l'intero storico bounded e non la preview.

La soglia cold-start predefinita è 20 eventi storici ed è configurabile con \`AEGIS_ANALYTICS_MIN_SAMPLES\`. Sotto soglia una finestra non è ready. Se lo storico dei 30 giorni raggiunge il limite eventi analytics configurato e risulta quindi troncato, i finding anomaly-like vengono soppressi invece di essere calcolati su uno storico incompleto.

### Prime analitiche di novità

Quando la baseline 30 giorni è ready, AEGIS può segnalare valori mai osservati nella baseline per:

- source IP;
- paese;
- ASN;
- username;
- SHA-256 di un payload osservato;
- artefatti URL/domain esatti già estratti deterministicamente in \`derived.ioc\`.

Ogni finding è classificato \`derived_analytic\`, contiene \`attribution: false\`, identifica l'evento anchor concreto, include valore misurato e numero di campioni della baseline e specifica che novità non significa maliciousness.

Lo SHA-256 del payload usato dalle analytics è un fingerprint deterministico del payload osservato memorizzato. Non viene promosso automaticamente a Threat Intelligence o reputation.

### Drill-down API

\`GET /api/v1/analytics/events/<event_id>\` restituisce le tre finestre di baseline, la policy cold-start/truncation, lo scope storico e i finding dell'evento.

Nessun finding viene scritto in \`observed\` e le analytics non riscrivono l'evento sorgente.
