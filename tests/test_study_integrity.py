from aegis_nexus.model import normalize_event
from aegis_nexus.study import explain, explain_session


def test_event_study_warns_when_collector_truncated_evidence():
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.130",
            "payload": "A" * 5000,
        },
    })

    italian = explain(event, "it")
    english = explain(event, "en")

    assert "collector" in italian["provenance"]
    assert any("tronc" in item.lower() for item in italian["limitations"])
    assert any("truncat" in item.lower() for item in english["limitations"])
    assert any("collector.normalization" in item for item in italian["soc_checklist"])


def test_event_study_explains_policy_redaction():
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "credential",
        "observed": {
            "source_ip": "203.0.113.131",
            "credential": {"username": "root", "password": "secret"},
        },
    })

    result = explain(event, "en")
    assert any("policy-redacted" in item for item in result["limitations"])


def test_session_study_distinguishes_heuristic_correlation_and_incomplete_evidence():
    event = normalize_event({
        "honeypot": "web-1",
        "event_type": "web.payload",
        "observed": {
            "source_ip": "203.0.113.132",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
            "payload": "B" * 5000,
        },
    })
    bundle = {
        "session": {
            "source_ip": "203.0.113.132",
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
        },
        "summary": {
            "event_count": 1,
            "payloads": 1,
            "correlation": {
                "method": "temporal_fallback",
                "strength": "heuristic",
                "basis": ["observed.source_ip", "event.timestamp", "session_gap"],
            },
        },
        "events": [event],
        "analysis": {"truncated": False},
    }

    result = explain_session(bundle, "en")
    assert any("lossy transformations" in item for item in result["facts"])
    assert any("collector-truncated evidence" in item for item in result["limitations"])
    assert any("correlation is heuristic" in item.lower() for item in result["limitations"])
