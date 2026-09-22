# Case management / Gestione casi

## English

AEGIS-NEXUS cases organize an investigation without changing the provenance of the underlying telemetry.

A case stores analyst-owned metadata: title, status, severity, summary, tags and notes. These fields are marked as analyst classifications or annotations. They are never promoted to observed facts.

Evidence is linked by reference to an existing event or correlated session. The case store does not copy commands, payloads, credentials or enrichment into a second long-lived evidence store. This avoids silently extending telemetry retention. When the source event/session is removed by the configured retention policy, the case keeps the identifier and marks the evidence reference as unavailable.

The case audit trail records creation, analyst updates, notes, evidence links and evidence removal. Notes are append-only through the current UI/API. Case reports include provenance labels and evidence availability.

Resource and lifecycle controls:
- maximum 1,000 evidence references per case;
- maximum 500 analyst notes per case;
- bounded title, summary, note and tag sizes;
- `AEGIS_MAX_CASES` bounds the total number of cases (default 10,000);
- `AEGIS_CASE_RETENTION_DAYS` can automatically delete only closed cases older than the configured period; the default `0` disables automatic case deletion;
- manual deletion is accepted only for a case already in `closed` state and cascades its notes, tags, evidence references and audit history without deleting source telemetry;
- operator authentication and API rate limiting apply to all case endpoints.

CSV exports neutralize cells beginning with spreadsheet formula prefixes so attacker-controlled telemetry cannot become a formula when opened in spreadsheet software.

A case severity is an analyst assessment. It does not overwrite the severity stored on source telemetry. Closing a case also does not delete or modify source evidence. Case metadata and analyst notes have a lifecycle separate from raw telemetry. Configure case retention deliberately, export anything that must be preserved before deletion, and avoid storing unnecessary secrets or personal data in notes.

---

## Italiano

I casi di AEGIS-NEXUS organizzano un'investigazione senza modificare la provenienza della telemetria sottostante.

Un caso conserva metadati dell'analista: titolo, stato, severità, sintesi, tag e note. Questi campi sono marcati come classificazioni o annotazioni dell'analista e non vengono mai trasformati in fatti osservati.

Le evidenze vengono collegate tramite riferimento a un evento esistente o a una sessione correlata. Il case store non copia comandi, payload, credenziali o enrichment in un secondo archivio persistente. In questo modo il caso non prolunga implicitamente la retention della telemetria. Quando evento/sessione sorgente vengono eliminati dalla policy di retention, il caso conserva l'identificativo e marca il riferimento come non più disponibile.

L'audit trail registra creazione, modifiche analista, note, collegamenti e rimozioni di evidenza. Le note sono append-only nell'interfaccia/API attuale. I report del caso includono provenienza e disponibilità dei riferimenti.

Controlli su risorse e lifecycle:
- massimo 1.000 riferimenti di evidenza per caso;
- massimo 500 note analista per caso;
- limiti su titolo, sintesi, note e tag;
- `AEGIS_MAX_CASES` limita il numero totale dei casi (default 10.000);
- `AEGIS_CASE_RETENTION_DAYS` può eliminare automaticamente soltanto casi chiusi più vecchi del periodo configurato; il valore predefinito `0` disabilita la cancellazione automatica;
- la cancellazione manuale è consentita solo per casi già in stato `closed` e rimuove in cascata note, tag, riferimenti e audit trail senza eliminare la telemetria sorgente;
- autenticazione operatore e rate limiting anche sugli endpoint dei casi.

Gli export CSV neutralizzano le celle che iniziano con prefissi interpretabili come formule, evitando che telemetria controllata dall'attaccante venga eseguita come formula quando il file viene aperto in un foglio di calcolo.

La severità del caso è una valutazione dell'analista e non sovrascrive la severità della telemetria sorgente. La chiusura di un caso non elimina né modifica le evidenze originali. Metadati del caso e note dell'analista hanno un ciclo di vita separato dalla telemetria raw: configura deliberatamente la retention, esporta ciò che deve essere conservato prima della cancellazione e non inserire nelle note segreti o dati personali non necessari.
