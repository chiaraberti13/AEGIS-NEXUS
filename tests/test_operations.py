import sqlite3
from datetime import datetime, timedelta, timezone

from aegis_nexus.app import create_app
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _event(timestamp, honeypot="ssh-decoy-01"):
    return normalize_event({
        "timestamp": timestamp,
        "honeypot": honeypot,
        "event_type": "connection",
        "observed": {
            "source_ip": "203.0.113.240",
            "service": "ssh",
            "protocol": "tcp",
            "destination_port": 22,
        },
    })


def test_collector_received_at_is_distinct_from_sensor_event_time_and_drives_retention(tmp_path):
    store = Store(str(tmp_path / "aegis.db"), retention_days=1)
    historical = "2001-01-01T00:00:00+00:00"
    saved = store.ingest(_event(historical))

    assert saved["timestamp"] == historical
    assert saved["received_at"] != historical
    persisted = store.get_event(saved["id"])
    assert persisted["received_at"] == saved["received_at"]

    # A newly received historical event is retained because retention is based
    # on collector receipt time, not the sensor-provided event timestamp.
    assert store.prune(1) == 0
    assert store.get_event(saved["id"]) is not None

    old_receipt = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    with store.connect() as conn:
        conn.execute("UPDATE events SET received_at=? WHERE id=?", (old_receipt, saved["id"]))

    assert store.prune(1) == 1
    assert store.get_event(saved["id"]) is None


def test_legacy_database_migrates_received_at_from_existing_event_timestamp(tmp_path):
    path = tmp_path / "legacy.db"
    timestamp = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, honeypot TEXT NOT NULL,
                service TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'unknown',
                destination_port INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL, last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, honeypot TEXT NOT NULL,
                event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT,
                session_id TEXT NOT NULL, protocol TEXT, service TEXT, destination_port INTEGER,
                country TEXT, asn TEXT, latitude REAL, longitude REAL,
                observed TEXT NOT NULL, enrichment TEXT NOT NULL, derived TEXT NOT NULL,
                hypotheses TEXT NOT NULL, schema_version TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );
        """)
        conn.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)",
            ("ses_legacy", "203.0.113.1", "ssh-old", "ssh", "tcp", 22, timestamp, timestamp, 1),
        )
        conn.execute(
            """
            INSERT INTO events(
                id,timestamp,honeypot,event_type,severity,source_ip,session_id,protocol,service,
                destination_port,country,asn,latitude,longitude,observed,enrichment,derived,hypotheses,schema_version
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "40000000-0000-4000-8000-000000000001",
                timestamp,
                "ssh-old",
                "connection",
                "info",
                "203.0.113.1",
                "ses_legacy",
                "tcp",
                "ssh",
                22,
                None,
                None,
                None,
                None,
                '{"source_ip":"203.0.113.1","service":"ssh","protocol":"tcp","destination_port":22}',
                "{}",
                "{}",
                "[]",
                "1.1",
            ),
        )

    store = Store(str(path), retention_days=30)
    migrated = store.get_event("40000000-0000-4000-8000-000000000001")
    assert migrated is not None
    assert migrated["received_at"] == timestamp


def test_operational_status_reports_receipt_freshness_without_online_claim(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "SENSOR_KEYS": {"ssh-decoy-01": "ssh-secret", "web-decoy-01": "web-secret"},
        "OPERATOR_API_KEY": "operator-secret",
        "MIN_FREE_BYTES": 0,
    })
    client = app.test_client()

    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/operations/status").status_code == 401

    created = client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "ssh-secret", "X-Aegis-Sensor": "ssh-decoy-01"},
        json={
            "timestamp": "2001-01-01T00:00:00Z",
            "honeypot": "ssh-decoy-01",
            "event_type": "connection",
            "observed": {
                "source_ip": "203.0.113.241",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": 22,
            },
        },
    )
    assert created.status_code == 201

    response = client.get(
        "/api/v1/operations/status?hours=24",
        headers={"X-Aegis-Operator-Key": "operator-secret"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["collector"]["ready"] is True
    telemetry = payload["telemetry"]
    assert telemetry["configured_sensors"] == 2
    assert telemetry["configured_with_recent_telemetry"] == 1
    assert "not proof" in telemetry["interpretation"].lower()
    assert "online or offline" in telemetry["interpretation"].lower()

    items = {item["sensor_id"]: item for item in telemetry["items"]}
    assert items["ssh-decoy-01"]["recent_events"] == 1
    assert items["ssh-decoy-01"]["last_received_at"]
    assert items["ssh-decoy-01"]["latest_event_timestamp"].startswith("2001-01-01")
    assert items["web-decoy-01"]["recent_events"] == 0
    assert items["web-decoy-01"]["last_received_at"] is None
    assert "ssh-secret" not in str(payload)
    assert "web-secret" not in str(payload)


def test_health_returns_503_when_storage_threshold_is_not_met(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
        "MIN_FREE_BYTES": 10**30,
    })
    response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.get_json() == {"status": "degraded"}


def test_frontend_has_truthful_operational_status_nodes(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'id="collector-status"' in html
    assert 'id="collector-status-dot"' in html
    assert 'id="sensor-telemetry-status"' in html
