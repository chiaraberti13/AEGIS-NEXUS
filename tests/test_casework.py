import pytest

from aegis_nexus.casework import (
    CaseValidationError,
    normalize_case_create,
    normalize_case_update,
    normalize_evidence,
    normalize_note,
)


def test_case_create_marks_only_bounded_analyst_fields():
    item = normalize_case_create({
        "title": "SSH credential review",
        "summary": "Investigate repeated usernames.",
        "status": "investigating",
        "severity": "high",
        "tags": ["ssh", "triage", "SSH"],
    })
    assert item["status"] == "investigating"
    assert item["severity"] == "high"
    assert item["tags"] == ["ssh", "triage"]


def test_case_validation_rejects_invalid_classification_and_control_characters():
    with pytest.raises(CaseValidationError):
        normalize_case_create({"title": "x", "severity": "urgent"})
    with pytest.raises(CaseValidationError):
        normalize_case_update({"summary": "bad\x00note"})


def test_case_evidence_is_reference_only_and_notes_are_bounded():
    assert normalize_evidence({"type": "event", "id": "abc"}) == {"type": "event", "id": "abc"}
    with pytest.raises(CaseValidationError):
        normalize_evidence({"type": "payload", "id": "abc"})
    assert normalize_note({"body": "Analyst observation."}) == "Analyst observation."
