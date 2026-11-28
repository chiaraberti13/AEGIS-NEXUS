# Storage backends & deployment profiles / Backend di storage e profili di deployment

## English

The collector and SOC console run on **SQLite**. The `StorageBackend`
protocol covers core persistence and has two implementations, `Store`
(SQLite) and the standalone `PostgresBackend` adapter (psycopg 3). See
[ADR 0002](adr/0002-storage-backend-postgresql.md) for the decision history.

### SQLite deployment

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
- SQLite serializes write transactions. Measure contention and ingestion
  latency under representative load before choosing a different deployment
  architecture.

### Standalone PostgreSQL adapter

Install the adapter dependencies with `pip install '.[postgres]'`. Python
callers instantiate `PostgresBackend(dsn)` directly. The Flask factory
and Docker Compose deployment currently use SQLite stores.
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
`PRAGMA user_version` — each step runs under a transaction-level advisory lock so
concurrent workers never double-apply, and a database written by a newer
release is refused, not migrated down.

Analytics surface, verified on SQLite and PostgreSQL: `page_events` (filters +
time window + cursor paging), `filter_options`, `detection_context`,
`behavioral_context`, `sensor_telemetry_observation` and `sensor_health`.

The case surface is now ported too (migration v2 adds `case_evidence` and
`case_history` tables): `add_case_evidence`, `case_report` and `case_timeline`
behave as on SQLite, so **all 26 `StorageBackend` contract methods are
implemented on PostgreSQL**. This covers the persistence protocol. The
full console also depends on SQLite-only capabilities such as session and alert
investigation, case notes, and sensor event sequencing. PostgreSQL uses one
connection per adapter instance. Its dashboard returns all-time event
and severity totals. Window and filter semantics and response fields used
by the console still need to be implemented. End-to-end console support and
concurrent deployment require separate integration and validation.

---

## Italiano

Il collector e la console SOC usano **SQLite**. Il protocollo
`StorageBackend` copre la persistenza di base e ha due implementazioni,
`Store` (SQLite) e l’adattatore autonomo `PostgresBackend` (psycopg 3).
L’[ADR 0002](adr/0002-storage-backend-postgresql.md) documenta le decisioni.

### Deployment con SQLite

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
- SQLite serializza le transazioni di scrittura. Misura la contesa e la
  latenza di ingestione con carichi rappresentativi prima di scegliere
  un’architettura di deployment diversa.

### Adattatore PostgreSQL autonomo

Installa le dipendenze dell’adattatore con `pip install '.[postgres]'`. I
chiamanti Python inizializzano direttamente `PostgresBackend(dsn)`. La
factory Flask e il deployment Docker Compose usano attualmente gli store
SQLite. L’adattatore implementa il
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
SQLite — ogni step gira sotto un advisory lock transazionale così worker
concorrenti non applicano due volte, e un database scritto da una release più
recente viene rifiutato, non migrato all'indietro.

Superficie analitica, verificata su SQLite e PostgreSQL: `page_events` (filtri +
finestra temporale + paginazione a cursore), `filter_options`,
`detection_context`, `behavioral_context`, `sensor_telemetry_observation` e
`sensor_health`.

Anche la superficie dei casi è ora portata (la migrazione v2 aggiunge le tabelle
`case_evidence` e `case_history`): `add_case_evidence`, `case_report` e
`case_timeline` si comportano come su SQLite, quindi **tutti i 26 metodi del
contratto `StorageBackend` sono implementati su PostgreSQL**. L’ambito è il
protocollo di persistenza. La console completa dipende anche da funzionalità
disponibili su SQLite, fra cui l’investigazione di sessioni e alert, le note
dei casi e il sequenziamento degli eventi dei sensori. PostgreSQL usa una
connessione per istanza dell’adattatore. La sua dashboard calcola totali
e conteggi per gravità sull’intero storico. Restano da implementare la
semantica di finestre e filtri e i campi della risposta usati dalla console. Il
supporto end-to-end e il deployment concorrente richiedono integrazione e
collaudo dedicati.
