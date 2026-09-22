from __future__ import annotations

import os
from pathlib import Path

from aegis_nexus.backup import backup_database


def main() -> None:
    source = Path(os.getenv("AEGIS_DATABASE_PATH", "./data/aegis.db"))
    destination_dir = Path(os.getenv("AEGIS_BACKUP_DIR", "./data/backups"))
    keep = int(os.getenv("AEGIS_BACKUP_KEEP", "14"))
    destination = backup_database(source, destination_dir, keep)
    print(destination)


if __name__ == "__main__":
    main()
