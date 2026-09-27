import json
from datetime import datetime, timezone
from pathlib import Path

from aegis_nexus.app import create_app
from aegis_nexus.detection import DetectionEngine
from aegis_nexus.detection_backtest import DetectionBacktester
from aegis_nexus.model import normalize_event
from aegis_nexus.suricata import normalize_eve_event


CORPUS = Path(__file__).parent / "fixtures" / "replay" / "v1" / "corpus.json"


def _load_corpus_events():
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    events = []
    for record in payload["records"]:
        if record["kind"] == "suricata_eve":
            events.append(normalize_event(normalize_eve_event(record["payload"], record["sensor_id"])))
        else:
            events.append(normalize_event(record["payload"]))
    return payload, events


def test_versioned_replay_corpus_covers_required_protocol_fixtures():
    corpus, _events = _load_corpus_events()
    assert corpus["corpus_version"] == "1.0"
    assert corpus["synthetic"] is True
    assert set(corpus["protocols"]) == {"ssh", "web", "ftp", "telnet", "suricata"}
    assert all(record["protocol_fixture"] in corpus["protocols"] for record in corpus["records"])


def test_detection_backtest_replays_versioned_corpus_without_writes():
    corpus, events = _load_corpus_events()
    result = DetectionBacktester(DetectionEngine()).run(events)
    assert result["writes_alerts"] is False
    assert result["applies_suppressions"] is False
    assert result["events_evaluated"] == len(events)
    assert set(corpus["expected_rule_ids"]) <= set(result["rule_hit_counts"])
    assert all(hit["evidence"] for hit in result["hits"])


def test_detection_backtest_rule_filter_is_exact():
    _corpus, events = _load_corpus_events()
    result = DetectionBacktester(DetectionEngine()).run(events, rule_id="download_attempt")
    assert result["total_hits"] == 1
    assert set(result["rule_hit_counts"]) == {"download_attempt"}
    assert {hit["rule_id"] for hit in result["hits"]} == {"download_attempt"}


def test_operator_backtest_reads_stored_history_without_creating_alerts(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "backtest.db"),
        "INGEST_API_KEY": "sensor-secret",
        "DETECTION_RULES_JSON": '{"rules":{"download_attempt":{"enabled":false}}}',
    })
    client = app.test_client()
    timestamp = datetime.now(timezone.utc).isoformat()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "timestamp": timestamp,
            "honeypot": "ssh-decoy-01",
            "event_type": "command",
            "observed": {
                "source_ip": "203.0.113.90",
                "destination_port": 22,
                "service": "ssh",
                "protocol": "tcp",
                "command": "wget http://example.invalid/replay",
            },
        },
    )
    assert response.status_code == 201
    assert client.get("/api/v1/alerts").get_json()["items"] == []

    backtest = client.post(
        "/api/v1/detection/backtest",
        json={"hours": 24, "rule_id": "download_attempt", "max_events": 100},
    )
    assert backtest.status_code == 200
    body = backtest.get_json()
    assert body["source"] == "stored_history"
    assert body["events_evaluated"] == 1
    assert body["total_hits"] == 0
    assert body["detection_config"]["rules"]["download_attempt"]["enabled"] is False
    assert client.get("/api/v1/alerts").get_json()["items"] == []


def test_backtest_api_rejects_unknown_rule(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "unknown.db")})
    response = app.test_client().post(
        "/api/v1/detection/backtest",
        json={"rule_id": "invented_rule"},
    )
    assert response.status_code == 422
    assert response.get_json()["detail"] == "unknown_detection_rule"
