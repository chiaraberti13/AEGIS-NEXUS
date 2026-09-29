from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


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
