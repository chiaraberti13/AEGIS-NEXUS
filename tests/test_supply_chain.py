from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "generate_sbom.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("aegis_sbom_script", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sbom_is_valid_cyclonedx_with_runtime_closure():
    sbom = _load_generator().generate_sbom(reproducible=True)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "aegis-nexus"

    names = {component["name"].lower() for component in sbom["components"]}
    # Declared runtime dependencies must be present.
    assert {"flask", "gunicorn", "geoip2", "paramiko"} <= names
    # Transitive runtime dependencies are resolved, not just the top level.
    assert {"werkzeug", "jinja2", "cryptography", "maxminddb"} <= names
    # Every component carries a PyPI package URL.
    for component in sbom["components"]:
        assert component["purl"].startswith("pkg:pypi/")
        assert component["version"]


def test_sbom_excludes_dev_and_tooling_packages():
    # The SBOM describes the shipped artifact (pip install .), so dev/tooling
    # packages must never leak into the runtime closure.
    sbom = _load_generator().generate_sbom(reproducible=True)
    names = {component["name"].lower() for component in sbom["components"]}
    assert "pytest" not in names
    assert "bandit" not in names
    assert "pip-audit" not in names


def test_sbom_reproducible_output_is_byte_stable():
    generate = _load_generator().generate_sbom
    first = json.dumps(generate(reproducible=True), sort_keys=False)
    second = json.dumps(generate(reproducible=True), sort_keys=False)
    assert first == second
    # Reproducible mode must not embed a timestamp.
    assert "timestamp" not in generate(reproducible=True)["metadata"]
