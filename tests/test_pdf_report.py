from __future__ import annotations

import io

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.pdf import text_to_pdf


def test_text_to_pdf_is_structurally_valid_and_escapes_hostile_text():
    hostile = "cmd: )(\\ <script>alert(1)</script>\nunicode: café €\n" + ("A" * 300)
    pdf = text_to_pdf("Report", hostile)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"xref" in pdf and b"trailer" in pdf
    # No HTML/script is rendered; the writer only emits text operators.
    assert b"/JavaScript" not in pdf and b"/JS" not in pdf


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    return app.test_client()


def _ingest_session(client):
    return client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "auth_attempt",
            "observed": {"source_ip": "203.0.113.40", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "credential": {"username": "root", "password": "x"},
                         "command": "<script>alert(1)</script>"},
        },
    ).get_json()["session_id"]


def test_case_pdf_export_is_operator_only_audited_and_pdf(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    case_id = client.post("/api/v1/cases", headers=operator, json={"title": "PDF case"}).get_json()["id"]

    assert client.get(f"/api/v1/reports/case/{case_id}.pdf").status_code == 401
    pdf = client.get(f"/api/v1/reports/case/{case_id}.pdf", headers=operator)
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.headers["Content-Disposition"].startswith("attachment;")
    assert pdf.data.startswith(b"%PDF-1.4")

    audit = client.get("/api/v1/audit", headers=operator).get_json()
    assert any(e["action"] == "export.case_report" and e["detail"].get("format") == "pdf" for e in audit["items"])


def test_session_pdf_shareable_profile_masks_ip(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    session_id = _ingest_session(client)

    internal = client.get(f"/api/v1/reports/session/{session_id}.pdf", headers=operator).data
    shareable = client.get(f"/api/v1/reports/session/{session_id}.pdf?profile=shareable", headers=operator).data

    def _text(data):
        reader = pypdf.PdfReader(io.BytesIO(data))
        return "".join(page.extract_text() for page in reader.pages)

    assert "203.0.113.40" in _text(internal)
    masked = _text(shareable)
    assert "203.0.113.40" not in masked
    assert "203.0.113.0/24" in masked
