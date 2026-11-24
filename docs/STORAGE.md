# Storage backends & deployment profiles / Backend di storage e profili di deployment

## English

The collector depends on a storage backend through the `StorageBackend`
interface (`src/aegis_nexus/storage_backend.py`). Today one backend ships:
**SQLite**, implemented by `Store` and used as the reference implementation. A
PostgreSQL backend is planned but not yet implemented — see
`docs/adr/0002-storage-backend-postgresql.md`.

### SQLite profile (current, recommended)

- Single-node, file-based (`AEGIS_DATABASE_PATH`), WAL journaling with
  `foreign_keys=ON`, `trusted_schema=OFF`, `secure_delete=ON` and a busy
  timeout on every connection.
- Forward-only migrations keyed on `PRAGMA user_version`, each in its own
  transaction with a pre-migration backup; a database written by a newer
  release is refused, not modified.
- Tamper-evident event hash chain; integrity checked with SQLite
  `quick_check`/`integrity_check`.
- Backups are consistent file copies (`make backup`) with automated restore
  verification (`make verify-restore`).
- Best for: a single collector instance (the common honeypot deployment),
  where operational simplicity and file-level backup/restore are advantages.
- Bounds: one writer process; very high sustained ingest across many
  concurrent writers is where a client/server database would help.

### PostgreSQL profile (planned, not yet implemented)

A PostgreSQL backend would target multi-node or high-concurrency deployments
(multiple collector workers/instances against a shared database). It is
**not shipped**: delivering it requires porting the migration strategy (a
transactional schema-version ledger instead of `PRAGMA user_version`), the
integrity/backup/hash-chain machinery, and the SQLite-specific SQL to
PostgreSQL, plus a backend-parity test suite proving identical investigation
results. Until then, run the SQLite profile. The decision and the required
work are recorded in ADR 0002.

Choosing a backend must never change investigation semantics (the evidence-first
model, provenance separation and bounded hostile-input handling are backend
independent); the `StorageBackend` interface exists to enforce that boundary.

---

## Italiano

Il collector dipende da un backend di storage tramite l'interfaccia
`StorageBackend` (`src/aegis_nexus/storage_backend.py`). Oggi è spedito un solo
backend: **SQLite**, implementato da `Store` e usato come implementazione di
riferimento. Un backend PostgreSQL è pianificato ma non ancora implementato —
vedi `docs/adr/0002-storage-backend-postgresql.md`.

### Profilo SQLite (attuale, consigliato)

- Nodo singolo, su file (`AEGIS_DATABASE_PATH`), journaling WAL con
  `foreign_keys=ON`, `trusted_schema=OFF`, `secure_delete=ON` e un busy timeout
  su ogni connessione.
- Migrazioni forward-only su `PRAGMA user_version`, ciascuna in transazione
  propria con backup pre-migrazione; un database scritto da una release più
  recente viene rifiutato, non modificato.
- Hash-chain degli eventi a prova di manomissione; integrità verificata con
  `quick_check`/`integrity_check` di SQLite.
- I backup sono copie di file consistenti (`make backup`) con verifica
  automatica del restore (`make verify-restore`).
- Ideale per: una singola istanza di collector (il deployment honeypot tipico),
  dove semplicità operativa e backup/restore a livello di file sono vantaggi.
- Limiti: un solo processo scrittore; un ingest sostenuto molto elevato con
  molti scrittori concorrenti è il caso in cui un database client/server aiuta.

### Profilo PostgreSQL (pianificato, non ancora implementato)

Un backend PostgreSQL servirebbe deployment multi-nodo o ad alta concorrenza
(più worker/istanze di collector verso un database condiviso). **Non è
spedito**: realizzarlo richiede il port della strategia di migrazione (un
ledger transazionale della versione di schema al posto di `PRAGMA user_version`),
delle macchine di integrità/backup/hash-chain e del SQL SQLite-specifico verso
PostgreSQL, più una suite di test di parità tra backend che dimostri risultati
investigativi identici. Fino ad allora, usa il profilo SQLite. La decisione e il
lavoro necessario sono registrati in ADR 0002.

La scelta del backend non deve mai cambiare la semantica investigativa (il
modello evidence-first, la separazione di provenance e la gestione bounded
dell'input ostile sono indipendenti dal backend); l'interfaccia `StorageBackend`
esiste per imporre questo confine.
