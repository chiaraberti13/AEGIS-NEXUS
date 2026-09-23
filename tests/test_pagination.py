from datetime import datetime, timedelta, timezone\n\nfrom aegis_nexus.app import create_app


def _ingest(client, event_id, timestamp, *, service="ssh", token=None):
    observed = {
        "source_ip": "203.0.113.200",
        "service": service,
        "protocol": "tcp",
        "destination_port": 22 if service == "ssh" else 80,
    }
    if token:
        observed["sensor_session_id"] = token
    return client.post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "secret"},
        json={
            "id": event_id,
            "timestamp": timestamp,
            "honeypot": "page-decoy",
            "event_type": "connection",
            "observed": observed,
        },
    )


def test_event_cursor_pagination_is_stable_with_equal_timestamps_and_new_ingest(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    ids = [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003",
        "00000000-0000-4000-8000-000000000004",
        "00000000-0000-4000-8000-000000000005",
    ]
    for event_id in ids:
        assert _ingest(client, event_id, "2026-09-22T20:00:00Z", token=event_id[-1]).status_code == 201

    first = client.get("/api/v1/events?limit=2").get_json()
    assert first["has_more"] is True
    assert first["next_cursor"]
    assert [item["id"] for item in first["items"]] == [ids[4], ids[3]]

    newest = "00000000-0000-4000-8000-000000000099"
    assert _ingest(client, newest, "2026-09-22T21:00:00Z", token="new").status_code == 201

    collected = [item["id"] for item in first["items"]]
    cursor = first["next_cursor"]
    while cursor:
        page = client.get("/api/v1/events", query_string={"limit": 2, "cursor": cursor}).get_json()
        collected.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]

    assert collected == list(reversed(ids))
    assert newest not in collected
    assert len(collected) == len(set(collected))


def test_event_cursor_is_bound_to_search_filter_and_window_scope(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    anchor = datetime.now(timezone.utc)
    assert _ingest(
        client,
        "10000000-0000-4000-8000-000000000001",
        (anchor - timedelta(hours=1)).isoformat(),
        service="ssh",
        token="a",
    ).status_code == 201
    assert _ingest(
        client,
        "10000000-0000-4000-8000-000000000002",
        (anchor - timedelta(hours=2)).isoformat(),
        service="ssh",
        token="b",
    ).status_code == 201

    first = client.get("/api/v1/events?limit=1&service=ssh&hours=24").get_json()
    assert first["next_cursor"]

    changed_filter = client.get(
        "/api/v1/events",
        query_string={"limit": 1, "service": "http", "hours": 24, "cursor": first["next_cursor"]},
    )
    assert changed_filter.status_code == 422
    assert changed_filter.get_json()["error"] == "invalid_cursor"

    changed_window = client.get(
        "/api/v1/events",
        query_string={"limit": 1, "service": "ssh", "hours": 72, "cursor": first["next_cursor"]},
    )
    assert changed_window.status_code == 422

    invalid = client.get("/api/v1/events?cursor=not-a-valid-cursor")
    assert invalid.status_code == 422


def test_session_cursor_pagination_uses_last_seen_and_id_tiebreaker(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    client = app.test_client()
    for index in range(5):
        event_id = f"20000000-0000-4000-8000-00000000000{index}"
        assert _ingest(
            client,
            event_id,
            "2026-09-22T20:00:00Z",
            token=f"session-{index}",
        ).status_code == 201

    collected = []
    cursor = None
    while True:
        query = {"limit": 2}
        if cursor:
            query["cursor"] = cursor
        page = client.get("/api/v1/sessions", query_string=query).get_json()
        collected.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            assert page["has_more"] is False
            break

    assert len(collected) == 5
    assert len(set(collected)) == 5


def test_frontend_exposes_historical_event_pagination_control(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "secret",
    })
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'id="event-load-older"' in html
    assert 'data-i18n="feed.loadOlder"' in html
