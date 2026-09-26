import hashlib
import io
import os

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.quarantine import QuarantineError, QuarantineStore
from aegis_nexus.sensors import web_decoy


def test_quarantine_store_hashes_bounds_and_uses_private_random_file(tmp_path):
    root = tmp_path / "quarantine"
    store = QuarantineStore(str(root), max_bytes=1024, max_files=2)
    payload = b"hostile-fixture-bytes"

    artifact = store.store(
        payload,
        sensor_id="web-decoy-01",
        original_name="../../payload.sh",
        content_type="application/x-sh",
    )

    assert artifact["sha256"] == hashlib.sha256(payload).hexdigest()
    assert artifact["size"] == len(payload)
    assert artifact["original_name"] == "payload.sh"
    assert artifact["quarantined"] is True
    assert artifact["executable"] is False
    assert artifact["inline_serving"] is False

    stored = root / f"{artifact['artifact_id']}.bin"
    assert stored.read_bytes() == payload
    if os.name != "nt":
        assert (stored.stat().st_mode & 0o777) == 0o600

    with pytest.raises(QuarantineError, match="artifact_too_large"):
        store.store(b"A" * 1025, sensor_id="web-decoy-01")


def test_quarantine_store_enforces_file_count_limit(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), max_bytes=1024, max_files=1)
    store.store(b"one", sensor_id="web-decoy-01")
    with pytest.raises(QuarantineError, match="quarantine_file_limit_reached"):
        store.store(b"two", sensor_id="web-decoy-01")


def test_collector_accepts_sensor_quarantine_upload_but_has_no_inline_get_route(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "QUARANTINE_DIR": str(tmp_path / "quarantine"),
        "QUARANTINE_MAX_BYTES": 1024,
        "QUARANTINE_MAX_FILES": 2,
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    payload = b"malware-fixture-not-executed"

    response = client.post(
        "/api/v1/quarantine",
        data=payload,
        headers={
            "X-Aegis-Key": "secret",
            "X-Aegis-Sensor": "web-decoy-01",
            "X-Aegis-Artifact-Name": "../../dropper.bin",
            "X-Aegis-Artifact-Type": "application/octet-stream",
            "Content-Type": "application/octet-stream",
        },
    )
    assert response.status_code == 201
    artifact = response.get_json()
    assert artifact["sha256"] == hashlib.sha256(payload).hexdigest()
    assert artifact["original_name"] == "dropper.bin"
    assert artifact["inline_serving"] is False

    get_response = client.get("/api/v1/quarantine")
    assert get_response.status_code == 405


def test_web_upload_quarantines_bytes_and_emits_metadata_only(monkeypatch):
    captured = []
    payload = b"web-upload-secret-payload"
    artifact = {
        "artifact_id": "artifact_fixture",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "original_name": "payload.bin",
        "content_type": "application/octet-stream",
    }
    monkeypatch.setattr(web_decoy.sensor, "quarantine_artifact", lambda *args, **kwargs: artifact)
    monkeypatch.setattr(
        web_decoy.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )

    client = web_decoy.app.test_client()
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(payload), "../../payload.bin")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 202
    assert response.get_json()["artifact_id"] == "artifact_fixture"
    event = next(args[1] for args, _kwargs in captured if args[0] == "artifact.quarantined")
    assert event["artifact"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert event["artifact"]["inline_serving"] is False
    assert payload.decode() not in str(event)


def test_web_upload_rejects_payload_over_quarantine_limit(monkeypatch):
    captured = []
    monkeypatch.setattr(web_decoy, "WEB_UPLOAD_MAX_BYTES", 8)
    monkeypatch.setattr(
        web_decoy.sensor,
        "emit",
        lambda *args, **kwargs: captured.append((args, kwargs)) or True,
    )
    client = web_decoy.app.test_client()
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"A" * 9), "large.bin")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 413
    assert not any(args[0] == "artifact.quarantined" for args, _kwargs in captured)
