from __future__ import annotations

import hashlib
import io
import json
import zipfile

from aegis_nexus.app import create_app
from aegis_nexus.evidence_bundle import build_evidence_bundle


def _read_zip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_bundle_manifest_hashes_every_file_and_is_reproducible():
    kwargs = dict(
        case_id="case_1",
        report_json={"case": {"id": "case_1"}, "generated_at": "2026-11-24T00:00:00+00:00"},
        report_markdown="# report\n",
        evidence_records=[{"name": "event-e1", "record": {"id": "e1", "observed": {"source_ip": "203.0.113.1"}}}],
        generated_at="2026-11-24T00:00:00+00:00",
    )
    first, manifest = build_evidence_bundle(**kwargs)
    second, _ = build_evidence_bundle(**kwargs)
    assert first == second  # fixed ZIP timestamps -> reproducible

    files = _read_zip(first)
    assert "case_report.json" in files
    assert "case_report.md" in files
    assert "manifest.json" in files
    assert "evidence/event-e1.json" in files

    # Every manifest entry's hash matches the actual file content, and the
    # manifest never tries to hash itself.
    by_path = {entry["path"]: entry for entry in manifest["entries"]}
    assert "manifest.json" not in by_path
    for path, entry in by_path.items():
        assert hashlib.sha256(files[path]).hexdigest() == entry["sha256"]
        assert entry["bytes"] == len(files[path])


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    return app.test_client()


def test_case_bundle_endpoint_is_operator_only_audited_attachment(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    event_id = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": "id"},
        },
    ).get_json()["id"]
    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "Bundle case"}).get_json()["id"]
    client.post(f"/api/v1/cases/{case_id}/evidence", headers=operator, json={"type": "event", "id": event_id})

    assert client.get(f"/api/v1/reports/case/{case_id}/bundle.zip").status_code == 401

    bundle = client.get(f"/api/v1/reports/case/{case_id}/bundle.zip", headers=operator)
    assert bundle.status_code == 200
    assert bundle.mimetype == "application/zip"
    assert bundle.headers["Content-Disposition"].startswith("attachment;")

    files = _read_zip(bundle.data)
    manifest = json.loads(files["manifest.json"])
    assert manifest["case_id"] == case_id
    assert manifest["algorithm"] == "sha256"
    # The linked event is bundled and its hash verifies.
    event_path = f"evidence/event-{event_id}.json"
    assert event_path in files
    entry = next(e for e in manifest["entries"] if e["path"] == event_path)
    assert hashlib.sha256(files[event_path]).hexdigest() == entry["sha256"]

    audit = client.get("/api/v1/audit", headers=operator).get_json()
    assert any(e["action"] == "export.case_bundle" for e in audit["items"])
