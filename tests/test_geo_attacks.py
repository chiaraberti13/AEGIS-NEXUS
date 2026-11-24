from __future__ import annotations

from aegis_nexus.app import create_app
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _geo_event(source_ip, lat, lon, *, severity="medium", accuracy=50):
    event = normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "severity": severity,
        "observed": {"source_ip": source_ip, "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": "id"},
    })
    event["enrichment"] = {
        "geo": {"source": "maxmind-local:test", "observed_at": event["timestamp"],
                "data": {"country": "US", "latitude": lat, "longitude": lon,
                         "accuracy_radius_km": accuracy}},
    }
    return event


def _plain_event(source_ip):
    return normalize_event({
        "honeypot": "ssh-1",
        "event_type": "command",
        "observed": {"source_ip": source_ip, "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": "id"},
    })


def test_geo_attacks_aggregates_points_with_accuracy_and_severity(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    e1 = _geo_event("203.0.113.5", 37.75, -122.68, severity="high", accuracy=50)
    store.ingest(e1, collector_received_at=e1["timestamp"])
    e2 = _geo_event("203.0.113.6", 37.75, -122.68, severity="low", accuracy=20)
    store.ingest(e2, collector_received_at=e2["timestamp"])

    geo = store.geo_attacks(hours=24)
    assert geo["provenance"] == "enrichment"
    assert len(geo["points"]) == 1  # same rounded location
    point = geo["points"][0]
    assert point["count"] == 2
    assert point["unique_source_ips"] == 2
    assert point["severity_level"] == 3  # max(high=3, low=1)
    assert point["accuracy_radius_km"] == 50  # max radius
    assert "not identity or attribution" in geo["caveat"]


def test_geo_attacks_puts_ungeolocated_ips_in_unmapped_bucket(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    # Private IP, no geo enrichment -> unmapped, never dropped.
    e = _plain_event("10.0.0.5")
    store.ingest(e, collector_received_at=e["timestamp"])

    geo = store.geo_attacks(hours=24)
    assert geo["points"] == []
    assert geo["unmapped"]["events"] == 1
    assert geo["unmapped"]["unique_source_ips"] == 1


def test_geo_attacks_treats_partial_coordinates_as_unmapped(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    # Latitude present but longitude missing -> cannot place the point -> unmapped.
    e = normalize_event({
        "honeypot": "ssh-1", "event_type": "command",
        "observed": {"source_ip": "203.0.113.9", "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": "id"},
    })
    e["enrichment"] = {"geo": {"source": "t", "observed_at": e["timestamp"],
                               "data": {"country": "US", "latitude": 37.75}}}
    store.ingest(e, collector_received_at=e["timestamp"])
    geo = store.geo_attacks(hours=24)
    assert geo["points"] == []
    assert geo["unmapped"]["events"] == 1


def test_geo_attacks_hard_caps_points(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    for i in range(3):
        e = _geo_event(f"203.0.113.{i}", 10.0 + i, 20.0 + i)
        store.ingest(e, collector_received_at=e["timestamp"])
    geo = store.geo_attacks(hours=24, max_points=1)
    assert len(geo["points"]) == 1
    assert geo["points_truncated"] is True
    assert geo["point_cap"] == 1


def test_geo_attacks_endpoint_is_operator_gated(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
        "OPERATOR_API_KEY": "operator-secret",
    })
    client = app.test_client()
    assert client.get("/api/v1/geo/attacks").status_code == 401
    ok = client.get("/api/v1/geo/attacks", headers={"X-Aegis-Operator-Key": "operator-secret"})
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["provenance"] == "enrichment"
    assert "points" in body and "unmapped" in body
