#!/usr/bin/env python3
"""Automated backup restore verification (read-only w.r.t. the backup).

Usage: verify_restore.py BACKUP [...]   -- exit 0 all ok, 1 a backup is unusable/tampered

For each backup it simulates a restore into a throwaway copy, runs SQLite
integrity_check, checks the schema version is supported and walks the event
hash chain, printing one JSON report per backup.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis_nexus.backup import verify_restore  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    status = 0
    for name in argv:
        report = verify_restore(Path(name))
        print(json.dumps(report, sort_keys=True))
        if not report.get("ok"):
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
