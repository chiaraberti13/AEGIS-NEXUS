# Supply chain & dependency assurance / Supply chain e garanzia delle dipendenze

## English

AEGIS-NEXUS keeps a deliberately small runtime dependency surface — **Flask,
gunicorn, geoip2, paramiko** — and ships only those (plus their transitive
closure) in the Docker image (`pip install .`). This page documents the local,
reproducible tooling that keeps that surface auditable.

CI note: these checks run in GitHub Actions (`.github/workflows/ci.yml`:
lint, typecheck, test, SAST, dependency-audit, secret-scan, SBOM, container) and
are also reproducible **locally** on any developer machine via the same `make`
targets.

### Pinned GitHub Actions (tag-move resistance)

Every action used by the CI workflow is pinned to an **immutable commit SHA**,
with a trailing `# vX.Y.Z` comment recording the human-readable version:

| Action | Version | Pinned commit |
|---|---|---|
| `actions/checkout` | v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-python` | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `gitleaks/gitleaks-action` | v2.3.9 | `ff98106e4c7b2bc287b24eaf42907196329070c7` |
| `aquasecurity/trivy-action` | v0.28.0 | `915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2` |

A version tag (`@v4`) is mutable — the upstream owner (or an attacker who
compromises the account) can move it to point at different code, so a tag pin
runs whatever that tag resolves to at run time. A commit-SHA pin runs exactly
the reviewed code and nothing else. `.github/dependabot.yml` keeps the pins
current: it opens PRs that bump both the SHA and the version comment when a new
release ships, so immutability does not mean staleness.

### SBOM (Software Bill of Materials)

`scripts/generate_sbom.py` emits a **CycloneDX 1.5** JSON SBOM describing the
runtime dependency closure only. It is:

- **offline** — it reads installed distribution metadata via
  `importlib.metadata`; it never contacts a network service;
- **scoped to the shipped artifact** — it walks the transitive closure of the
  declared runtime dependencies and intentionally excludes development and
  tooling packages (pytest, bandit, pip-audit, …), so the SBOM matches what the
  Docker image installs, not the build host;
- **deterministic** — `--reproducible` omits the timestamp so repeated runs
  produce byte-identical output, suitable for diffing across releases;
- **honest about gaps** — any declared dependency that cannot be resolved
  against installed metadata is surfaced under
  `metadata.properties[aegis:unresolved-dependency]`, never silently dropped.

```
make sbom                 # print the SBOM to stdout
make sbom OUT=sbom.json   # write it to a file
python scripts/generate_sbom.py --reproducible --output sbom.json
```

### SAST (bandit) with a reviewed baseline

`.bandit-baseline.json` is a reviewed bandit baseline: every finding it contains
has been analysed and accepted as safe or by-design, so `make sast` reports only
**new** findings introduced after the baseline. Regenerate it with
`bandit -r src -f json -o .bandit-baseline.json` after a refactor that moves
accepted findings between modules, and re-review the diff before committing.

Accepted findings and why they are safe:

- **B608 (SQL built with f-strings):** the interpolated part is always an
  identifier taken from a fixed allowlist or module constant (e.g.
  `_EVENT_FILTERS`, `HASHED_COLUMNS`, the PostgreSQL backend's `_FILTER_EXPR`,
  or a fixed `WHERE`/`ORDER BY` fragment), and all values are bound with
  placeholders (`?` for SQLite, `%s` for psycopg) and length-limited. No
  attacker input reaches a SQL identifier. These live in the SQLite store
  modules (`store_events.py`, `store_sessions.py`, `store_cases.py`,
  `store_analytics.py` — extracted from `store.py`) and in
  `postgres_backend.py`.
- **B101 (assert):** redundant type-narrowing hints after an explicit validation
  that already raised on invalid input, plus module-load contract checks (e.g.
  `postgres_backend.py` asserting every `StorageBackend` method is present) — not
  validation of hostile input.
- **B104 (bind 0.0.0.0):** by design — a honeypot sensor must be reachable;
  isolation is enforced by the Docker networks and the egress guard.
- **B310 (urlopen):** the URL is the operator-configured collector endpoint,
  never attacker-controlled (`forwarding.py`; scheme validated, `# noqa: S310`).
- **B110 (try/except/pass):** best-effort event forwarding in `forwarding.py`
  must never crash or block the collector on a downstream/logging error, so a
  failed optional forward is swallowed after being logged — it is not hiding a
  security check.

```
make sast                 # bandit -r src --baseline .bandit-baseline.json
```

When a change legitimately alters the findings, regenerate the baseline with
`bandit -r src -f json -o .bandit-baseline.json` and review the diff.

### Dependency vulnerability scanning (pip-audit)

```
make audit                # pip-audit over the environment
```

Scan the **runtime** closure in a clean environment (`pip install .`) to avoid
noise from build/test tooling that is not shipped. CVEs reported only for
packages that are absent from the SBOM (pytest, setuptools, wheel, …) do not
affect the shipped artifact.

CI audits the hash-locked closure (`pip-audit --requirement requirements.lock`).

#### Accepted dependency advisories (triage)

| Advisory | Package | Decision | Rationale |
|---|---|---|---|
| `PYSEC-2026-2858` | paramiko 4.0.0 | **accepted, no fix released** | "rsakey.py allows the SHA-1 algorithm." paramiko runs **server-side in the SSH decoy** (a honeypot that deliberately accepts any client, with an ephemeral generated host key) — it is never used as a client verifying trusted signatures, so SHA-1 in `rsakey.py` is not exploitable in the honeypot threat model. No fixed release exists yet (fix is only upstream commit `a448945`). Re-evaluate and drop the ignore when a fixed paramiko release ships. Pinned with `--ignore-vuln` in CI. |

---

## Italiano

AEGIS-NEXUS mantiene volutamente una superficie di dipendenze runtime ridotta —
**Flask, gunicorn, geoip2, paramiko** — e nell'immagine Docker spedisce solo
quelle (più la loro chiusura transitiva) via `pip install .`. Questa pagina
documenta gli strumenti locali e riproducibili che mantengono quella superficie
verificabile.

Nota CI: questi controlli girano in GitHub Actions (`.github/workflows/ci.yml`:
lint, typecheck, test, SAST, dependency-audit, secret-scan, SBOM, container) e
sono anche riproducibili **in locale** su qualsiasi macchina di sviluppo con gli
stessi target `make`.

### GitHub Actions pinnate (resistenza allo spostamento dei tag)

Ogni action usata dal workflow CI è pinnata a uno **SHA di commit immutabile**,
con un commento finale `# vX.Y.Z` che registra la versione leggibile:

| Action | Versione | Commit pinnato |
|---|---|---|
| `actions/checkout` | v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-python` | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `gitleaks/gitleaks-action` | v2.3.9 | `ff98106e4c7b2bc287b24eaf42907196329070c7` |
| `aquasecurity/trivy-action` | v0.28.0 | `915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2` |

Un tag di versione (`@v4`) è mutabile — il proprietario upstream (o un attaccante
che ne compromette l'account) può spostarlo su codice diverso, quindi un pin a
tag esegue ciò che quel tag risolve al momento dell'esecuzione. Un pin a SHA di
commit esegue esattamente il codice revisionato e nient'altro.
`.github/dependabot.yml` mantiene aggiornati i pin: apre PR che aggiornano sia lo
SHA sia il commento di versione all'uscita di una nuova release, così
l'immutabilità non significa obsolescenza.

### SBOM (distinta dei componenti software)

`scripts/generate_sbom.py` produce un SBOM JSON **CycloneDX 1.5** che descrive la
sola chiusura delle dipendenze runtime. È:

- **offline** — legge i metadati delle distribuzioni installate via
  `importlib.metadata`; non contatta alcun servizio di rete;
- **limitato all'artefatto spedito** — percorre la chiusura transitiva delle
  dipendenze runtime dichiarate ed esclude di proposito i pacchetti di sviluppo
  e tooling (pytest, bandit, pip-audit, …), così l'SBOM corrisponde a ciò che
  installa l'immagine Docker, non all'host di build;
- **deterministico** — `--reproducible` omette il timestamp così run ripetute
  producono output identico byte-per-byte, adatto al confronto tra release;
- **onesto sulle lacune** — qualunque dipendenza dichiarata non risolvibile nei
  metadati installati viene esposta sotto
  `metadata.properties[aegis:unresolved-dependency]`, mai scartata in silenzio.

```
make sbom                 # stampa l'SBOM su stdout
make sbom OUT=sbom.json   # lo scrive su file
python scripts/generate_sbom.py --reproducible --output sbom.json
```

### SAST (bandit) con baseline rivista

`.bandit-baseline.json` è una baseline bandit rivista: ogni finding che contiene
è stato analizzato e accettato come sicuro o by-design, così `make sast` segnala
solo i finding **nuovi** introdotti dopo la baseline. Rigenerala con
`bandit -r src -f json -o .bandit-baseline.json` dopo un refactor che sposta
finding accettati tra moduli, rivedendo il diff prima del commit.

Finding accettati e perché sono sicuri:

- **B608 (SQL con f-string):** la parte interpolata è sempre un identificatore
  preso da una allowlist fissa o da una costante di modulo (es. `_EVENT_FILTERS`,
  `HASHED_COLUMNS`, il `_FILTER_EXPR` del backend PostgreSQL, o un frammento
  `WHERE`/`ORDER BY` fisso) e tutti i valori sono parametrizzati con placeholder
  (`?` per SQLite, `%s` per psycopg) e limitati in lunghezza. Nessun input
  dell'attaccante raggiunge un identificatore SQL. Vivono nei moduli dello store
  SQLite (`store_events.py`, `store_sessions.py`, `store_cases.py`,
  `store_analytics.py` — estratti da `store.py`) e in `postgres_backend.py`.
- **B101 (assert):** *type-narrowing* ridondanti dopo una validazione esplicita
  che ha già sollevato su input invalido, più controlli di contratto a load-time
  (es. `postgres_backend.py` che verifica la presenza di ogni metodo
  `StorageBackend`) — non validazioni di input ostile.
- **B104 (bind 0.0.0.0):** by-design — un sensore honeypot deve essere
  raggiungibile; l'isolamento è garantito dalle reti Docker e dall'egress guard.
- **B310 (urlopen):** l'URL è l'endpoint del collector configurato
  dall'operatore, mai controllato dall'attaccante (`forwarding.py`; schema
  validato, `# noqa: S310`).
- **B110 (try/except/pass):** l'inoltro eventi best-effort in `forwarding.py`
  non deve mai far crashare o bloccare il collector per un errore a valle o di
  logging, quindi un inoltro opzionale fallito viene assorbito dopo il log — non
  nasconde un controllo di sicurezza.

```
make sast                 # bandit -r src --baseline .bandit-baseline.json
```

Quando una modifica altera legittimamente i finding, rigenera la baseline con
`bandit -r src -f json -o .bandit-baseline.json` e rivedi il diff.

### Scansione vulnerabilità dipendenze (pip-audit)

```
make audit                # pip-audit sull'ambiente
```

Esegui la scansione sulla chiusura **runtime** in un ambiente pulito
(`pip install .`) per evitare rumore dal tooling di build/test non spedito. I
CVE riportati solo per pacchetti assenti dall'SBOM (pytest, setuptools, wheel, …)
non riguardano l'artefatto spedito.
