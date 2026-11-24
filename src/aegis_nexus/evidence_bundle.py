"""Chain-of-custody evidence bundle for a case.

Packages a case report and the records it references into a single ZIP with a
``manifest.json`` that lists the SHA-256 of every other file in the bundle. The
bundle is inert data: it is produced from already export-sanitized structures,
never executes or renders attacker-controlled content, and is served only as an
authenticated, audited attachment.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from typing import Any

BUNDLE_MANIFEST_SCHEMA_VERSION = "1.0"
# Fixed ZIP timestamp so the same inputs yield a byte-identical archive
# (content integrity lives in the manifest hashes, but reproducibility helps
# chain-of-custody comparisons).
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_evidence_bundle(
    *,
    case_id: str,
    report_json: dict[str, Any],
    report_markdown: str,
    evidence_records: list[dict[str, Any]],
    generated_at: str,
) -> tuple[bytes, dict[str, Any]]:
    """Build a (zip_bytes, manifest) pair.

    ``evidence_records`` is a list of ``{"name": str, "record": dict}`` already
    resolved by the caller; names are made safe and de-duplicated here.
    """
    files: list[tuple[str, bytes]] = [
        ("case_report.json", _canonical(report_json)),
        ("case_report.md", report_markdown.encode("utf-8")),
    ]
    used: set[str] = set()
    for entry in evidence_records:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(entry.get("name") or "evidence"))[:120]
        path = f"evidence/{safe}.json"
        # De-duplicate collided names deterministically.
        suffix = 1
        base = path
        while path in used:
            path = base[:-5] + f"-{suffix}.json"
            suffix += 1
        used.add(path)
        files.append((path, _canonical(entry.get("record"))))

    manifest = {
        "schema_version": BUNDLE_MANIFEST_SCHEMA_VERSION,
        "report_type": "evidence_bundle_manifest",
        "case_id": case_id,
        "generated_at": generated_at,
        "algorithm": "sha256",
        "entry_count": len(files),
        "entries": [
            {"path": path, "bytes": len(data), "sha256": _sha256(data)}
            for path, data in files
        ],
        "note": (
            "Hashes cover every file except this manifest. Records are evidence "
            "references and bounded summaries, not re-executed or rendered content."
        ),
    }
    manifest_bytes = _canonical(manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in files:
            info = zipfile.ZipInfo(path, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        archive.writestr(zipfile.ZipInfo("manifest.json", date_time=_ZIP_DATE), manifest_bytes)
    return buffer.getvalue(), manifest
