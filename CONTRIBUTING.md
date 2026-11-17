# Contributing to AEGIS-NEXUS

Thank you for contributing. The goal is to keep changes reviewable, reproducible and aligned with the repository's actual scope: an evidence-first honeypot, SOC analysis and threat-research platform with strict provenance and isolation boundaries.

## Before opening a change
1. Read `README.md`, `SECURITY.md` and this document.
2. Search existing issues before opening a duplicate.
3. Use a dedicated branch and keep each pull request focused on one coherent change.
4. Never include credentials, private data, production exports, copyrighted material you cannot redistribute, or data obtained without authorization.
5. Report vulnerabilities privately according to `SECURITY.md`, not in a public issue.

## Local setup
```bash
python -m pip install -e ".[dev]"
cp .env.example .env
```

## Quality checks
Run the relevant checks before submitting:
```bash
pytest
python -m ruff check .
python -m mypy src
```
If a command does not apply to the files you changed, explain that explicitly in the pull request.

## Engineering expectations
- Preserve existing architecture and public interfaces unless the change intentionally revises them.
- Validate untrusted input and fail safely.
- Keep secrets in environment/configuration mechanisms, never in source control.
- Add or update tests for behavioural changes.
- Write documentation in English and keep both README editions semantically aligned.
- Keep examples safe, reproducible and scoped to owned or explicitly authorized systems/data.
- Prefer small dependencies with a clear purpose; review licence, maintenance status and security impact before adding one.

## Pull requests
Describe: **what changed**, **why**, **security/privacy impact**, **how it was tested**, and any compatibility or migration implications. Use clear commit messages and avoid mixing unrelated refactors with functional changes.

## Review
A change can be revised or rejected when it is unsafe, out of scope, insufficiently tested, legally unclear, or inconsistent with project architecture. Participation is governed by `CODE_OF_CONDUCT.md`.

---

## Reporting and contribution checks

Use the [issue templates](https://github.com/chiaraberti13/AEGIS-NEXUS/issues/new/choose) and check for duplicates first. Useful context: Python version, sensor or SOC view, browser and synthetic telemetry.

Write community and technical documentation in English; maintain equivalent English and Italian READMEs. Preserve existing application translations. Fill in the pull request template with commands, results and checks not performed, including the reason. Use synthetic examples without secrets or personal data.

See [the code of conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md) and [accessibility statement](ACCESSIBILITY.md). Report vulnerabilities only through the security policy process.
