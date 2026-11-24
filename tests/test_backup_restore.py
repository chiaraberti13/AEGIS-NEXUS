from __future__ import annotations

from pathlib import Path

from aegis_nexus.backup import backup_database, verify_restore
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _store_with_events(tmp_path, n=3):
    store = Store(str(tmp_path / "aegis.db"))
    for i in range(n):
        event = normalize_event({
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {"source_ip": f"203.0.113.{i}", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": "id"},
        })
        store.ingest(event, collector_received_at=event["timestamp"])
    return store


def test_verify_restore_passes_for_a_fresh_backup(tmp_path):
    store = _store_with_events(tmp_path, n=3)
    backup = backup_database(Path(store.path), tmp_path / "backups")

    report = verify_restore(backup)
    assert report["ok"] is True
    assert report["integrity_ok"] is True
    assert report["schema_supported"] is True
    assert report["events"] == 3
    assert report["chain_ok"] is True
    assert report["chain_problems"] == []


def test_verify_restore_reports_missing_backup(tmp_path):
    report = verify_restore(tmp_path / "does-not-exist.db")
    assert report["ok"] is False
    assert report["error"] == "backup_not_found"


def test_verify_restore_rejects_a_corrupt_file(tmp_path):
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database" * 10)
    report = verify_restore(corrupt)
    assert report["ok"] is False


def test_verify_restore_does_not_touch_the_backup(tmp_path):
    store = _store_with_events(tmp_path, n=1)
    backup = backup_database(Path(store.path), tmp_path / "backups")
    before = backup.read_bytes()
    verify_restore(backup)
    assert backup.read_bytes() == before  # original backup is untouched
