from types import SimpleNamespace

from aegis_nexus.app import create_app
from aegis_nexus.enrichment import LocalGeoIPEnricher


class FakeCityReader:
    def __init__(self):
        self.calls = []
        self.closed = False

    def city(self, ip):
        self.calls.append(ip)
        return SimpleNamespace(
            country=SimpleNamespace(iso_code="US"),
            city=SimpleNamespace(name="Mountain View"),
            location=SimpleNamespace(
                latitude=37.4,
                longitude=-122.1,
                accuracy_radius=20,
                time_zone="America/Los_Angeles",
            ),
        )

    def close(self):
        self.closed = True


class FakeASNReader:
    def __init__(self):
        self.calls = []
        self.closed = False

    def asn(self, ip):
        self.calls.append(ip)
        return SimpleNamespace(
            autonomous_system_number=15169,
            autonomous_system_organization="Example ASN",
        )

    def close(self):
        self.closed = True


def test_local_enrichment_is_offline_evidence_with_provenance():
    city = FakeCityReader()
    asn = FakeASNReader()
    enricher = LocalGeoIPEnricher(city_reader=city, asn_reader=asn)
    event = {
        "observed": {"source_ip": "8.8.8.8"},
        "enrichment": {},
    }
    enriched = enricher.enrich(event)

    assert event["enrichment"] == {}
    assert enriched["enrichment"]["geo"]["data"]["country"] == "US"
    assert enriched["enrichment"]["geo"]["source"].startswith("maxmind-local:")
    assert enriched["enrichment"]["geo"]["observed_at"]
    assert enriched["enrichment"]["asn"]["data"]["asn"] == "AS15169"
    assert enriched["enrichment"]["asn"]["data"]["organization"] == "Example ASN"
    assert enricher.status()["network_requests"] is False


def test_local_enrichment_skips_non_global_ips_and_preserves_existing_data():
    city = FakeCityReader()
    asn = FakeASNReader()
    enricher = LocalGeoIPEnricher(city_reader=city, asn_reader=asn)

    private = {"observed": {"source_ip": "192.168.10.20"}, "enrichment": {}}
    assert enricher.enrich(private) == private
    assert city.calls == []
    assert asn.calls == []

    existing = {
        "observed": {"source_ip": "8.8.8.8"},
        "enrichment": {
            "geo": {
                "source": "sensor-provided",
                "observed_at": "2026-09-22T18:00:00+00:00",
                "data": {"country": "ZZ"},
            }
        },
    }
    enriched = enricher.enrich(existing)
    assert enriched["enrichment"]["geo"]["source"] == "sensor-provided"
    assert enriched["enrichment"]["geo"]["data"]["country"] == "ZZ"
    assert enriched["enrichment"]["asn"]["data"]["asn"] == "AS15169"


def test_collector_persists_local_geoip_as_external_enrichment(tmp_path):
    city = FakeCityReader()
    asn = FakeASNReader()
    enricher = LocalGeoIPEnricher(city_reader=city, asn_reader=asn)
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "ENRICHER": enricher,
    })
    client = app.test_client()
    response = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "honeypot": "dns-observer-01",
            "event_type": "connection",
            "observed": {
                "source_ip": "8.8.8.8",
                "service": "dns",
                "protocol": "udp",
                "destination_port": 53,
            },
        },
    )
    assert response.status_code == 201
    event_id = response.get_json()["id"]
    stored = client.get(f"/api/v1/events/{event_id}").get_json()
    assert stored["country"] == "US"
    assert stored["asn"] == "AS15169"
    assert stored["enrichment"]["geo"]["source"].startswith("maxmind-local:")

    status = client.get("/api/v1/enrichment/status").get_json()
    assert status["mode"] == "local_offline"
    assert status["network_requests"] is False
    assert status["city"]["ready"] is True
    assert status["asn"]["ready"] is True
