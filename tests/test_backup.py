import sqlite3

from scripts.backup import backup_database


def test_backup_database_copies_data_and_rotates(tmp_path):
    source = tmp_path / "aegis.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE sample(value TEXT)")
        conn.execute("INSERT INTO sample(value) VALUES('evidence')")

    backup_dir = tmp_path / "backups"
    first = backup_database(source, backup_dir, keep=1)
    with sqlite3.connect(first) as conn:
        assert conn.execute("SELECT value FROM sample").fetchone()[0] == "evidence"

    second = backup_database(source, backup_dir, keep=1)
    assert second.exists()
    assert len(list(backup_dir.glob("aegis-*.db"))) == 1
