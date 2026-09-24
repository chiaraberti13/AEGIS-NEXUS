import hashlib
import io

from aegis_nexus.app import create_app
from aegis_nexus.pcap import PcapCaptureProvider


PCAP_FIXTURE = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20


def _create_session(client):
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-decoy-01",
            "event_type": "connection",
            "observed": {
                "source_ip": "203.0.113.90",
                "source_port": 50123,
                "destination_port": 22,
                "service": "ssh",
                "protocol": "tcp",
            },
        },
    )
    assert response.status_code == 201
    return response.get_json()["session_id"]


def _app(tmp_path, **extra):
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
        "PCAP_ENABLED": True,
        "PCAP_DIR": str(tmp_path / "pcap"),
        "PCAP_MAX_BYTES": 4096,
        "PCAP_RETENTION_DAYS": 7,
        "PCAP_MAX_FILES": 10,
    }
    config.update(extra)
    return create_app(config)


def test_pcap_upload_is_operator_only_bounded_hashed_and_session_linked(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    session_id = _create_session(client)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    denied = client.post(
        "/api/v1/pcap",
        data={"session_id": session_id, "pcap": (io.BytesIO(PCAP_FIXTURE), "fixture.pcap")},
        content_type="multipart/form-data",
    )
    assert denied.status_code == 401

    response = client.post(
        "/api/v1/pcap",
        headers=operator,
        data={"session_id": session_id, "pcap": (io.BytesIO(PCAP_FIXTURE), "../../fixture.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    item = response.get_json()
    assert item["session_id"] == session_id
    assert item["size_bytes"] == len(PCAP_FIXTURE)
    assert item["sha256"] == hashlib.sha256(PCAP_FIXTURE).hexdigest()
    assert item["format"] == "pcap"
    assert item["capture_provider"] == "operator_upload"

    listing = client.get(f"/api/v1/pcap?session_id={session_id}", headers=operator)
    assert listing.status_code == 200
    assert listing.get_json()["items"][0]["id"] == item["id"]

    download = client.get(f"/api/v1/pcap/{item['id']}/download", headers=operator)
    assert download.status_code == 200
    assert download.data == PCAP_FIXTURE
    assert download.headers["X-Aegis-SHA256"] == item["sha256"]
    assert "../../fixture.pcap" not in download.headers["Content-Disposition"]


def test_pcap_upload_rejects_unknown_session_invalid_format_and_size(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    session_id = _create_session(client)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    invalid = client.post(
        "/api/v1/pcap",
        headers=operator,
        data={"session_id": session_id, "pcap": (io.BytesIO(b"not-a-pcap-file"), "bad.pcap")},
        content_type="multipart/form-data",
    )
    assert invalid.status_code == 422

    unknown = client.post(
        "/api/v1/pcap",
        headers=operator,
        data={"session_id": "missing-session", "pcap": (io.BytesIO(PCAP_FIXTURE), "fixture.pcap")},
        content_type="multipart/form-data",
    )
    assert unknown.status_code == 422

    oversized = PCAP_FIXTURE + b"A" * 5000
    too_large = client.post(
        "/api/v1/pcap",
        headers=operator,
        data={"session_id": session_id, "pcap": (io.BytesIO(oversized), "large.pcap")},
        content_type="multipart/form-data",
    )
    assert too_large.status_code == 422


def test_pcap_mode_is_disabled_by_default(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
        "PCAP_DIR": str(tmp_path / "pcap"),
    })
    client = app.test_client()
    session_id = _create_session(client)
    response = client.post(
        "/api/v1/pcap",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
        data={"session_id": session_id, "pcap": (io.BytesIO(PCAP_FIXTURE), "fixture.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 409
    assert response.get_json()["error"] == "pcap_disabled"


class _FixtureCaptureProvider:
    name = "fixture-capture"

    def capture(self, session_id: str, max_bytes: int) -> bytes:
        assert session_id
        assert max_bytes >= len(PCAP_FIXTURE)
        return PCAP_FIXTURE


def test_optional_pcap_capture_provider_is_bounded_and_persisted(tmp_path):
    app = _app(tmp_path, PCAP_CAPTURE_PROVIDER=_FixtureCaptureProvider())
    client = app.test_client()
    session_id = _create_session(client)
    response = client.post(
        "/api/v1/pcap/capture",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
        json={"session_id": session_id},
    )
    assert response.status_code == 201
    item = response.get_json()
    assert item["capture_provider"] == "fixture-capture"
    assert item["session_id"] == session_id
    assert item["sha256"] == hashlib.sha256(PCAP_FIXTURE).hexdigest()
