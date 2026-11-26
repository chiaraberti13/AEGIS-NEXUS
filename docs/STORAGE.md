# Storage backends & deployment profiles / Backend di storage e profili di deployment

## English

The collector depends on a storage backend through the `StorageBackend`
interface (`src/aegis_nexus/storage_backend.py`). **SQLite**, implemented by
`Store`, is the default reference backend. An opt-in **PostgreSQL** backend
(`PostgresBackend`, psycopg 3) implements core persistence — see
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

### PostgreSQL profile (opt-in, core persistence)

`PostgresBackend` (psycopg 3) targets multi-node or high-concurrency
deployments. Install with `pip install '.[postgres]'` and point it at a DSN.
It implements the **core persistence** contract — event ingest/fetch (event
JSON in a `jsonb` column, provenance classes preserved), collector counters,
operator cases (CRUD + list + retention prune), sensor heartbeats, sensor nonce
anti-replay, operational health and a SQL dashboard rollup — verified against a
real PostgreSQL 16 by the cross-backend compatibility suite
(`tests/test_backend_compatibility.py`, run on SQLite and PostgreSQL; the PG leg
runs wherever `AEGIS_TEST_POSTGRES_DSN` is set, including the CI `postgres:16`
service).

Migrations: forward-only with a transactional `schema_migrations` ledger
(`apply_pg_migrations`), the PostgreSQL equivalent of SQLite's
`PRAGMA user_version` — each step runs under a session advisory lock so
concurrent workers never double-apply, and a database written by a newer
release is refused, not migrated down.

Analytics surface, ported incrementally and verified on SQLite and PostgreSQL:
`page_events` (filters + time window + cursor paging), `filter_options`,
`detection_context` and `behavioral_context` are implemented. Not yet ported
(methods raise `PostgresBackendUnsupported` rather than returning silently wrong
data): sensor telemetry/health rollups, and the case report/timeline/evidence
methods (which also need the richer case schema ported first). For the full
console experience run the SQLite profile; the remaining work is tracked in
ADR 0002.

Choosing a backend must never change investigation semantics (the evidence-first
model, provenance separation and bounded hostile-input handling are backend
independent); the `StorageBackend` interface exists to enforce that boundary.

---

## Italiano

Il collector dipende da un backend di storage tramite l'interfaccia
`StorageBackend` (`src/aegis_nexus/storage_backend.py`). **SQLite**,
implementato da `Store`, è il backend di riferimento predefinito. Un backend
**PostgreSQL** opt-in (`PostgresBackend`, psycopg 3) implementa la persistenza
di base — vedi `docs/adr/0002-storage-backend-postgresql.md`.

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

### Profilo PostgreSQL (opt-in, persistenza di base)

`PostgresBackend` (psycopg 3) serve deployment multi-nodo o ad alta concorrenza.
Installa con `pip install '.[postgres]'` e puntalo a un DSN. Implementa il
contratto di **persistenza di base** — ingest/fetch eventi (JSON evento in una
colonna `jsonb`, classi di provenance preservate), counter del collector, casi
operatore (CRUD + lista + prune retention), heartbeat sensori, anti-replay dei
nonce, health operativa e un rollup dashboard in SQL — verificato contro un
PostgreSQL 16 reale dalla suite di compatibilità cross-backend
(`tests/test_backend_compatibility.py`, eseguita su SQLite e PostgreSQL; il
ramo PG gira ovunque sia impostato `AEGIS_TEST_POSTGRES_DSN`, incluso il service
CI `postgres:16`).

Migrazioni: forward-only con un ledger transazionale `schema_migrations`
(`apply_pg_migrations`), l'equivalente PostgreSQL del `PRAGMA user_version` di
SQLite — ogni step gira sotto un advisory lock di sessione così worker
concorrenti non applicano due volte, e un database scritto da una release più
recente viene rifiutato, non migrato all'indietro.

Superficie analitica, portata in modo incrementale e verificata su SQLite e
PostgreSQL: `page_events` (filtri + finestra temporale + paginazione a cursore),
`filter_options`, `detection_context` e `behavioral_context` sono implementati.
Non ancora portato (i metodi sollevano `PostgresBackendUnsupported` invece di
restituire dati silenziosamente errati): i rollup telemetria/salute sensori e i
metodi report/timeline/evidenze dei casi (che richiedono prima il port dello
schema casi più ricco). Per l'esperienza completa della console usa il profilo
SQLite; il lavoro residuo è tracciato in ADR 0002.

La scelta del backend non deve mai cambiare la semantica investigativa (il
modello evidence-first, la separazione di provenance e la gestione bounded
dell'input ostile sono indipendenti dal backend); l'interfaccia `StorageBackend`
esiste per imporre questo confine.
