# Contributing to AEGIS-NEXUS

AEGIS-NEXUS accepts improvements to sensors, parsers, analytics, UI, documentation and study content when they preserve the security boundaries of the project.

Required invariants:
- never execute captured commands or payloads on the collector;
- never commit secrets, live credentials or personal data;
- keep `observed`, `enrichment`, `derived` and `hypotheses` distinct;
- MITRE ATT&CK and CVE mappings must carry both rationale and evidence;
- simulation/demo events must be explicitly marked with `derived.data_mode = "simulation"`;
- do not weaken container isolation, request bounds, credential redaction or operator-access controls;
- preserve upstream licences and provenance for any imported dependency or dataset.

Before opening a pull request, run `pytest -q` and ensure the Docker image builds successfully.
