# Case management / Gestione dei casi

## English

AEGIS-NEXUS cases are analyst workspaces for grouping telemetry references, notes and investigation state without changing the provenance of the underlying evidence.

A case stores:

- analyst classification: title, status, severity, summary and tags;
- analyst notes with immutable timestamps;
- references to event and session identifiers;
- an audit trail for creation, updates, evidence links/removals and notes.

Case severity and status are **analyst assessments**, not observed facts. The API and UI expose this explicitly through `classification_provenance: analyst`.

Evidence links do not copy attacker payloads, credentials or complete telemetry into the case tables. They reference the original event/session. If retention removes the source telemetry, the case keeps the identifier and marks the evidence as unavailable. This avoids silently extending telemetry retention through case creation.

Case JSON/CSV reports contain reference metadata and analyst annotations. They do not export cleartext credential secrets.

Operators should define a retention policy for analyst notes and case metadata separately from raw honeypot telemetry. Do not paste secrets or unnecessary personal data into analyst notes.

---

## Italiano

I casi di AEGIS-NEXUS sono workspace dell’analista per raggruppare riferimenti alla telemetria, note e stato dell’investigazione senza modificare la provenienza delle evidenze originali.

Un caso conserva:

- classificazione dell’analista: titolo, stato, severità, sintesi e tag;
- note dell’analista con timestamp immutabile;
- riferimenti agli identificativi di eventi e sessioni;
- audit trail di creazione, modifiche, collegamento/rimozione evidenze e note.

Severità e stato del caso sono **valutazioni dell’analista**, non fatti osservati. API e interfaccia lo rendono esplicito tramite `classification_provenance: analyst`.

I collegamenti alle evidenze non copiano payload, credenziali o telemetria completa nelle tabelle dei casi. Mantengono un riferimento all’evento/sessione originale. Se la retention elimina la telemetria sorgente, il caso conserva l’identificativo e marca l’evidenza come non più disponibile. In questo modo la creazione di un caso non estende implicitamente la retention della telemetria.

I report JSON/CSV dei casi contengono metadata dei riferimenti e annotazioni dell’analista. Non esportano credenziali in chiaro.

È necessario definire una retention separata per note e metadata dei casi rispetto alla telemetria honeypot. Non inserire nelle note segreti o dati personali non necessari.
