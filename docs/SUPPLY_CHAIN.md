# Supply chain & dependency assurance / Supply chain e garanzia delle dipendenze

## English

AEGIS-NEXUS keeps a deliberately small runtime dependency surface — **Flask,
gunicorn, geoip2, paramiko** — and ships only those (plus their transitive
closure) in the Docker image (`pip install .`). This page documents the local,
reproducible tooling that keeps that surface auditable.

CI note: the repository currently ships no GitHub Actions workflow. These
checks are therefore run **locally** and are reproducible on any developer
machine; wiring them into a CI workflow is a deployment decision for the
maintainer.

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
**new** findings introduced after the baseline.

Accepted findings and why they are safe:

- **B608 (SQL built with f-strings):** the interpolated part is always an
  identifier taken from a fixed allowlist or module constant (e.g.
  `_EVENT_FILTERS`, `HASHED_COLUMNS`), and all values are bound with `?`
  placeholders and length-limited. No attacker input reaches a SQL identifier.
- **B101 (assert):** the two asserts are redundant type-narrowing hints after an
  explicit validation that already raised on invalid input, not validation of
  hostile input.
- **B104 (bind 0.0.0.0):** by design — a honeypot sensor must be reachable;
  isolation is enforced by the Docker networks and the egress guard.
- **B310 (urlopen):** the URL is the operator-configured collector endpoint,
  never attacker-controlled.

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

---

## Italiano

AEGIS-NEXUS mantiene volutamente una superficie di dipendenze runtime ridotta —
**Flask, gunicorn, geoip2, paramiko** — e nell'immagine Docker spedisce solo
quelle (più la loro chiusura transitiva) via `pip install .`. Questa pagina
documenta gli strumenti locali e riproducibili che mantengono quella superficie
verificabile.

Nota CI: al momento il repository non include alcun workflow GitHub Actions.
Questi controlli vengono quindi eseguiti **in locale** e sono riproducibili su
qualsiasi macchina di sviluppo; integrarli in una CI è una decisione di
deployment del manutentore.

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
solo i finding **nuovi** introdotti dopo la baseline.

Finding accettati e perché sono sicuri:

- **B608 (SQL con f-string):** la parte interpolata è sempre un identificatore
  preso da una allowlist fissa o da una costante di modulo (es. `_EVENT_FILTERS`,
  `HASHED_COLUMNS`) e tutti i valori sono parametrizzati con `?` e limitati in
  lunghezza. Nessun input dell'attaccante raggiunge un identificatore SQL.
- **B101 (assert):** i due assert sono *type-narrowing* ridondanti dopo una
  validazione esplicita che ha già sollevato su input invalido, non validazioni
  di input ostile.
- **B104 (bind 0.0.0.0):** by-design — un sensore honeypot deve essere
  raggiungibile; l'isolamento è garantito dalle reti Docker e dall'egress guard.
- **B310 (urlopen):** l'URL è l'endpoint del collector configurato
  dall'operatore, mai controllato dall'attaccante.

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
