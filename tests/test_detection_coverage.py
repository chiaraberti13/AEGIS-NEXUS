from __future__ import annotations

import json
import re

from aegis_nexus.detection_config import DetectionConfig
from aegis_nexus.detection_coverage import _RULE_TECHNIQUES, mitre_coverage

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_coverage_only_maps_implemented_rules():
    # Every rule we map must be an implemented rule; no mapping may reference a
    # rule id that does not exist in the configuration.
    implemented = set(DetectionConfig.defaults().rules)
    assert set(_RULE_TECHNIQUES) <= implemented


def test_coverage_is_evidence_backed_and_well_formed():
    coverage = mitre_coverage(DetectionConfig.defaults())
    assert coverage["technique_count"] == len(coverage["techniques"])
    assert coverage["techniques"], "expected at least one technique"
    for technique in coverage["techniques"]:
        assert _TECHNIQUE_RE.match(technique["technique"])
        assert technique["name"] and technique["tactic"]
        assert technique["rules"], "a listed technique must have contributing rules"
        # Every contributing rule carries a rationale (never invented).
        for rule in technique["rules"]:
            assert rule["rationale"].strip()
            assert rule["rule_id"] in DetectionConfig.defaults().rules


def test_severity_only_passthrough_rule_is_unmapped_not_invented():
    coverage = mitre_coverage(DetectionConfig.defaults())
    unmapped = {item["rule_id"] for item in coverage["unmapped_rules"]}
    # A severity-only IDS passthrough must not be forced onto a technique.
    assert "suricata_high_severity" in unmapped


def test_disabling_a_rule_flips_technique_enabled_state():
    # path_traversal_sequence is the only rule mapped to T1083; disabling it
    # must keep the technique listed (still implemented) but mark it disabled.
    config = DetectionConfig.from_json(
        json.dumps({"rules": {"path_traversal_sequence": {"enabled": False}}})
    )
    coverage = mitre_coverage(config)
    t1083 = next(t for t in coverage["techniques"] if t["technique"] == "T1083")
    assert t1083["enabled"] is False
    assert all(rule["enabled"] is False for rule in t1083["rules"])
    # Enabled count never exceeds total count.
    assert coverage["enabled_technique_count"] <= coverage["technique_count"]


def test_coverage_endpoint_requires_operator_and_returns_view(tmp_path):
    from aegis_nexus.app import create_app

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()

    assert client.get("/api/v1/detections/coverage").status_code == 401
    ok = client.get(
        "/api/v1/detections/coverage",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
    )
    assert ok.status_code == 200
    payload = ok.get_json()
    assert payload["schema_version"]
    assert "not actor attribution" in payload["caveat"]
    assert payload["techniques"]
