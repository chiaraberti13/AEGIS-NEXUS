from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup_database(source: Path, destination_dir: Path, keep: int = 14) -> Path:
    if not source.exists():
        raise FileNotFoundError(source)
    destination_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = destination_dir / f"aegis-{timestamp}.db"

    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()

    try:
        destination.chmod(0o600)
    except OSError:
        pass

    keep = max(1, min(int(keep), 365))
    backups = sorted(
        destination_dir.glob("aegis-*.db"),
        key=lambda item: item.stat().st_mtime_ns,
        reverse=True,
    )
    for stale in backups[keep:]:
        stale.unlink(missing_ok=True)
    return destination
