from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup_database(source: Path, destination_dir: Path, keep: int = 14) -> Path:
    if not source.exists():
        raise FileNotFoundError(source)
    destination_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
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
    backups = sorted(destination_dir.glob("aegis-*.db"), key=lambda item: item.stat().st_mtime, reverse=True)
    for stale in backups[keep:]:
        stale.unlink(missing_ok=True)
    return destination


def main() -> None:
    source = Path(os.getenv("AEGIS_DATABASE_PATH", "./data/aegis.db"))
    destination_dir = Path(os.getenv("AEGIS_BACKUP_DIR", "./data/backups"))
    keep = int(os.getenv("AEGIS_BACKUP_KEEP", "14"))
    destination = backup_database(source, destination_dir, keep)
    print(destination)


if __name__ == "__main__":
    main()
