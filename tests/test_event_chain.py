import sqlite3
import uuid

from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _event(command="id"):
    return normalize_event({
        "id": str(uuid.uuid4()),
        "honeypot": "ssh-decoy-01",
        "event_type": "command",
        "observed": {"source_ip": "203.0.113.10", "service": "ssh", "protocol": "tcp",
                     "destination_port": 22, "command": command},
    })


def _store(tmp_path, n=5):
    store = Store(str(tmp_path / "chain.db"))
    ids = [store.ingest(_event(f"cmd{i}"))["id"] for i in range(n)]
    return store, ids


def test_new_events_form_a_verifiable_chain(tmp_path):
    store, _ = _store(tmp_path)
    report = store.verify_event_chain()
    assert report["ok"] and report["records_verified"] == 5
    assert report["head_seq"] == 5 and report["problems"] == []


def test_editing_a_stored_record_is_detected(tmp_path):
    store, ids = _store(tmp_path)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET observed=? WHERE id=?", ('{"command":"forged"}', ids[2]))
    report = store.verify_event_chain()
    assert not report["ok"]
    assert report["problems"][0]["type"] == "record_hash_mismatch"
    assert report["problems"][0]["event_id"] == ids[2]


def test_deleting_a_middle_record_is_detected(tmp_path):
    store, ids = _store(tmp_path)
    with sqlite3.connect(store.path) as conn:
        conn.execute("DELETE FROM events WHERE id=?", (ids[2],))
    kinds = {p["type"] for p in store.verify_event_chain()["problems"]}
    assert {"sequence_gap", "broken_link"} <= kinds


def test_truncating_the_tail_is_detected_via_head(tmp_path):
    store, ids = _store(tmp_path)
    with sqlite3.connect(store.path) as conn:
        conn.execute("DELETE FROM events WHERE id=?", (ids[-1],))
    kinds = {p["type"] for p in store.verify_event_chain()["problems"]}
    assert "head_mismatch" in kinds


def test_retention_pruning_of_oldest_records_keeps_chain_valid(tmp_path):
    store, ids = _store(tmp_path)
    with sqlite3.connect(store.path) as conn:
        conn.execute("DELETE FROM events WHERE id IN (?,?)", (ids[0], ids[1]))
    report = store.verify_event_chain()
    assert report["ok"] and report["pruned_before"] == 3


def test_pre_chain_rows_are_reported_not_trusted(tmp_path):
    store, ids = _store(tmp_path, 2)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET chain_seq=NULL, prev_hash=NULL, record_hash=NULL WHERE id=?", (ids[0],))
    report = store.verify_event_chain()
    assert report["unchained_legacy"] == 1


def test_offline_verifier_exit_codes(tmp_path):
    import subprocess, sys
    store, ids = _store(tmp_path)
    script = "scripts/verify_integrity.py"
    ok = subprocess.run([sys.executable, script, store.path], capture_output=True, text=True)
    assert ok.returncode == 0
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET severity='critical' WHERE id=?", (ids[1],))
    bad = subprocess.run([sys.executable, script, store.path], capture_output=True, text=True)
    assert bad.returncode == 1
    missing = subprocess.run([sys.executable, script, str(tmp_path / "nope.db")], capture_output=True, text=True)
    assert missing.returncode == 2


def test_offline_verifier_checks_backups(tmp_path):
    import subprocess, sys
    from pathlib import Path
    from aegis_nexus.backup import backup_database
    store, ids = _store(tmp_path)
    backup = backup_database(Path(store.path), tmp_path / "bk", 3)
    script = "scripts/verify_integrity.py"
    assert subprocess.run([sys.executable, script, str(backup)], capture_output=True, text=True).returncode == 0
    with sqlite3.connect(backup) as conn:
        conn.execute("DELETE FROM events WHERE id=?", (ids[1],))
    bad = subprocess.run([sys.executable, script, store.path, str(backup)], capture_output=True, text=True)
    assert bad.returncode == 1
