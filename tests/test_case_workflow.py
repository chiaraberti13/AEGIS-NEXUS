from __future__ import annotations

import pytest

from aegis_nexus.app import create_app
from aegis_nexus.casework import CaseValidationError, normalize_case_create, normalize_case_update


def _client(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
        "OPERATOR_IDENTITY": "analyst-1",
    })
    return app.test_client()


def test_normalize_defaults_and_validates_workflow_fields():
    created = normalize_case_create({"title": "T"})
    assert created["priority"] == "normal"
    assert created["owner"] == ""
    assert created["conclusion"] == ""

    with pytest.raises(CaseValidationError):
        normalize_case_create({"title": "T", "priority": "sometime"})
    with pytest.raises(CaseValidationError):
        normalize_case_update({"priority": "sometime"})


def test_case_owner_defaults_to_acting_operator_and_fields_persist(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}

    created = client.post(
        "/api/v1/cases",
        headers=operator,
        json={"title": "Credential review", "priority": "high"},
    )
    assert created.status_code == 201
    case = created.get_json()
    assert case["priority"] == "high"
    assert case["owner"] == "analyst-1"  # defaulted to the acting operator
    assert case["conclusion"] == ""
    case_id = case["id"]

    updated = client.patch(
        f"/api/v1/cases/{case_id}",
        headers=operator,
        json={"status": "closed", "conclusion": "Confirmed benign scanner.", "owner": "analyst-2"},
    )
    assert updated.status_code == 200
    body = updated.get_json()
    assert body["conclusion"] == "Confirmed benign scanner."
    assert body["owner"] == "analyst-2"
    assert body["status"] == "closed"


def test_case_report_includes_workflow_fields(tmp_path):
    client = _client(tmp_path)
    operator = {"X-Aegis-Operator-Key": "operator-secret"}
    case_id = client.post(
        "/api/v1/cases",
        headers=operator,
        json={"title": "Report case", "priority": "urgent", "conclusion": "Escalated to IR."},
    ).get_json()["id"]

    report = client.get(f"/api/v1/reports/case/{case_id}.md?lang=en", headers=operator)
    assert report.status_code == 200
    text = report.get_data(as_text=True)
    assert "Priority" in text and "urgent" in text
    assert "Owner" in text and "analyst-1" in text
    assert "### Conclusion" in text
    assert "Escalated to IR." in text

    report_it = client.get(f"/api/v1/reports/case/{case_id}.md?lang=it", headers=operator)
    assert "Priorità" in report_it.get_data(as_text=True)
    assert "Conclusione" in report_it.get_data(as_text=True)
