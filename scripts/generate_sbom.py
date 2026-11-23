#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for the AEGIS-NEXUS runtime dependency closure.

Offline and deterministic: it reads installed distribution metadata via
``importlib.metadata`` and walks the transitive closure of the project's
declared runtime dependencies only — the same set the Docker image installs
(``pip install .``). Development and tooling packages (pytest, bandit, …) are
intentionally excluded so the SBOM describes the shipped artifact, not the
build host.

Usage:
    generate_sbom.py [--output FILE] [--reproducible]

    --output FILE     write the SBOM to FILE (default: stdout)
    --reproducible    omit the timestamp and serial number so repeated runs
                      produce byte-identical output (useful for tests/builds)

Exit codes: 0 ok · 2 project metadata unreadable.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any

try:
    from packaging.requirements import Requirement
except ModuleNotFoundError:  # pragma: no cover - packaging ships with pip/setuptools
    Requirement = None  # type: ignore[assignment]

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_SPEC_VERSION = "1.5"


def _project_metadata() -> dict[str, Any]:
    with _PYPROJECT.open("rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project") or {}
    return {
        "name": str(project.get("name") or "aegis-nexus"),
        "version": str(project.get("version") or "0.0.0"),
        "dependencies": list(project.get("dependencies") or []),
    }


def _requirement_name(spec: str) -> str | None:
    """Best-effort distribution name from a requirement string, no markers."""
    if Requirement is not None:
        try:
            return Requirement(spec).name
        except Exception:
            return None
    # Minimal fallback: take the leading name token.
    token = spec.strip()
    for sep in (";", "[", "(", "=", "<", ">", "!", "~", " "):
        idx = token.find(sep)
        if idx != -1:
            token = token[:idx]
    return token or None


def _runtime_requirements(dist: metadata.Distribution) -> list[str]:
    """Base (non-extra) requirements of a distribution whose markers hold now."""
    result: list[str] = []
    for raw in dist.requires or []:
        if Requirement is None:
            name = _requirement_name(raw)
            if name:
                result.append(name)
            continue
        try:
            req = Requirement(raw)
        except Exception:
            continue
        # Skip anything gated on an extra: the image installs no extras.
        marker = req.marker
        if marker is not None and not marker.evaluate({"extra": ""}):
            continue
        result.append(req.name)
    return result


def _license_of(dist: metadata.Distribution) -> str | None:
    meta = dist.metadata
    declared = meta.get("License")
    if declared and declared.strip() and declared.strip().lower() != "unknown":
        return declared.strip().splitlines()[0][:128]
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License :: "):
            return classifier.split(" :: ")[-1][:128]
    return None


def _component(dist: metadata.Distribution) -> dict[str, Any]:
    name = dist.metadata["Name"]
    version = dist.version
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower()}@{version}",
    }
    license_expression = _license_of(dist)
    if license_expression:
        component["licenses"] = [{"license": {"name": license_expression}}]
    return component


def build_closure(top_level: list[str]) -> tuple[list[metadata.Distribution], list[str]]:
    """Resolve the transitive closure of top-level requirement names.

    Returns the resolved distributions (deduplicated) and the names that could
    not be resolved against installed metadata (recorded, never silently
    dropped).
    """
    seen: dict[str, metadata.Distribution] = {}
    unresolved: set[str] = set()
    queue = [name for spec in top_level if (name := _requirement_name(spec))]
    while queue:
        name = queue.pop()
        key = name.lower().replace("_", "-")
        if key in seen or key in unresolved:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            unresolved.add(key)
            continue
        seen[key] = dist
        queue.extend(_runtime_requirements(dist))
    return list(seen.values()), sorted(unresolved)


def generate_sbom(*, reproducible: bool = False) -> dict[str, Any]:
    project = _project_metadata()
    dists, unresolved = build_closure(project["dependencies"])
    components = sorted(
        (_component(dist) for dist in dists),
        key=lambda item: (item["name"].lower(), item["version"]),
    )

    metadata_block: dict[str, Any] = {
        "component": {
            "type": "application",
            "name": project["name"],
            "version": project["version"],
            "purl": f"pkg:pypi/{project['name'].lower()}@{project['version']}",
        },
        "tools": {"components": [{"type": "application", "name": "aegis-sbom", "version": "1"}]},
    }
    if not reproducible:
        metadata_block["timestamp"] = datetime.now(timezone.utc).isoformat()

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "version": 1,
        "metadata": metadata_block,
        "components": components,
    }
    if unresolved:
        # Evidence loss is disclosed, never silent: surface names we could not
        # resolve against installed metadata so the SBOM is honest.
        sbom["metadata"]["properties"] = [
            {"name": "aegis:unresolved-dependency", "value": name} for name in unresolved
        ]
    return sbom


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate a CycloneDX SBOM (offline).")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--reproducible", action="store_true")
    args = parser.parse_args(argv)

    try:
        sbom = generate_sbom(reproducible=args.reproducible)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"cannot read project metadata: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(sbom, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
