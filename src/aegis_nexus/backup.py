from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def backup_database(
    source: Path,
    destination_dir: Path,
    keep: int = 14,
    *,
    name_prefix: str = "aegis",
) -> Path:
    if not source.exists():
        raise FileNotFoundError(source)
    destination_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_prefix = "".join(
        character for character in name_prefix if character.isalnum() or character in "-_"
    )
    if not safe_prefix or len(safe_prefix) > 96:
        raise ValueError("invalid backup name prefix")
    destination = destination_dir / f"{safe_prefix}-{timestamp}.db"
    temporary = destination.with_suffix(".db.part")

    source_connection: sqlite3.Connection | None = None
    destination_connection: sqlite3.Connection | None = None
    try:
        source_connection = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
        destination_connection = sqlite3.connect(temporary)
        temporary.chmod(0o600)
        source_connection.backup(destination_connection)
        check = destination_connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise sqlite3.DatabaseError("SQLite backup quick_check failed")
        destination_connection.close()
        destination_connection = None
        source_connection.close()
        source_connection = None
        temporary.replace(destination)
    except BaseException:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)

    keep = max(1, min(int(keep), 365))
    backups = sorted(
        destination_dir.glob("aegis-*.db"),
        key=lambda item: item.stat().st_mtime_ns,
        reverse=True,
    )
    for stale in backups[keep:]:
        stale.unlink(missing_ok=True)
    return destination


def verify_restore(backup: Path) -> dict[str, Any]:
    """Simulate restoring ``backup`` and verify it is usable.

    Copies the backup to a throwaway location (never touching the original),
    then runs SQLite ``integrity_check``, reads the schema version and walks the
    event hash chain. Read-only with respect to the backup. Returns a report;
    ``ok`` is true only when the copy is structurally sound, the schema is a
    supported version and the hash chain shows no tamper evidence.
    """
    report: dict[str, Any] = {
        "file": backup.name,
        "ok": False,
        "integrity_ok": False,
        "schema_version": None,
        "schema_supported": False,
        "events": None,
        "chain_ok": None,
        "chain_problems": [],
    }
    if not backup.exists():
        report["error"] = "backup_not_found"
        return report

    # Imported lazily: migrations.py imports this module for pre-migration
    # backups, so a top-level import would be circular.
    from .event_chain import verify_chain
    from .migrations import LATEST_SCHEMA_VERSION, schema_version

    tmp_dir = Path(tempfile.mkdtemp(prefix="aegis-restore-"))
    restored = tmp_dir / "restored.db"
    try:
        shutil.copy2(backup, restored)
        conn = sqlite3.connect(restored)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            report["integrity_ok"] = bool(integrity) and integrity[0] == "ok"
            version = schema_version(conn)
            report["schema_version"] = version
            report["schema_supported"] = 1 <= int(version) <= LATEST_SCHEMA_VERSION
            report["events"] = int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            chain = verify_chain(conn)
            report["chain_ok"] = bool(chain.get("ok"))
            report["chain_problems"] = chain.get("problems") or []
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        report["error"] = type(exc).__name__
        return report
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    report["ok"] = bool(
        report["integrity_ok"]
        and report["schema_supported"]
        and report["chain_ok"]
        and not report["chain_problems"]
    )
    return report
