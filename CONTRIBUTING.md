# Contributing to AEGIS-NEXUS

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

## English

Thank you for contributing. The goal is to keep changes reviewable, reproducible and aligned with the repository's actual scope: an evidence-first honeypot, SOC analysis and threat-research platform with strict provenance and isolation boundaries.

### Before opening a change
1. Read `README.md`, `SECURITY.md` and this document.
2. Search existing issues before opening a duplicate.
3. Use a dedicated branch and keep each pull request focused on one coherent change.
4. Never include credentials, private data, production exports, copyrighted material you cannot redistribute, or data obtained without authorization.
5. Report vulnerabilities privately according to `SECURITY.md`, not in a public issue.

### Local setup
```bash
python -m pip install -e ".[dev]"\ncp .env.example .env
```

### Quality checks
Run the relevant checks before submitting:
```bash
pytest\npython -m ruff check .\npython -m mypy src
```
If a command does not apply to the files you changed, explain that explicitly in the pull request.

### Engineering expectations
- Preserve existing architecture and public interfaces unless the change intentionally revises them.
- Validate untrusted input and fail safely.
- Keep secrets in environment/configuration mechanisms, never in source control.
- Add or update tests for behavioural changes.
- Update English documentation first, then keep the Italian documentation semantically aligned.
- Keep examples safe, reproducible and scoped to owned or explicitly authorized systems/data.
- Prefer small dependencies with a clear purpose; review licence, maintenance status and security impact before adding one.

### Pull requests
Describe: **what changed**, **why**, **security/privacy impact**, **how it was tested**, and any compatibility or migration implications. Use clear commit messages and avoid mixing unrelated refactors with functional changes.

### Review
A change can be revised or rejected when it is unsafe, out of scope, insufficiently tested, legally unclear, or inconsistent with project architecture. Participation is governed by `CODE_OF_CONDUCT.md`.

---

## Italiano

Grazie per il contributo. L'obiettivo è mantenere le modifiche verificabili, riproducibili e coerenti con il perimetro reale del repository: an evidence-first honeypot, SOC analysis and threat-research platform with strict provenance and isolation boundaries.

### Prima di proporre una modifica
1. Leggi `README.md`, `SECURITY.md` e questo documento.
2. Verifica che non esista già una issue equivalente.
3. Usa un branch dedicato e mantieni ogni pull request focalizzata.
4. Non inserire credenziali, dati privati, export di produzione, materiale non redistribuibile o dati ottenuti senza autorizzazione.
5. Le vulnerabilità vanno segnalate privatamente seguendo `SECURITY.md`.

### Configurazione locale
```bash
python -m pip install -e ".[dev]"\ncp .env.example .env
```

### Controlli qualità
Esegui i controlli pertinenti prima della pull request:
```bash
pytest\npython -m ruff check .\npython -m mypy src
```
Se un controllo non è applicabile alla modifica, dichiaralo nella pull request.

### Aspettative tecniche
- Mantieni architettura e interfacce pubbliche salvo modifiche intenzionali e documentate.
- Valida gli input non fidati e usa comportamenti fail-safe.
- Mantieni i segreti fuori dal repository.
- Aggiorna o aggiungi test per le modifiche di comportamento.
- Aggiorna prima la documentazione inglese e mantieni quella italiana semanticamente equivalente.
- Usa esempi sicuri e limitati a sistemi/dati propri o autorizzati.
- Valuta necessità, licenza, manutenzione e impatto di sicurezza prima di aggiungere dipendenze.

### Pull request e review
Descrivi **cosa cambia**, **perché**, **impatto sicurezza/privacy**, **test eseguiti** ed eventuali implicazioni di compatibilità o migrazione. I contributi possono essere revisionati o rifiutati se non sicuri, fuori perimetro, non testati o legalmente poco chiari. Si applica `CODE_OF_CONDUCT.md`.
