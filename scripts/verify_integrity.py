#!/usr/bin/env python3
"""Offline integrity check for the AEGIS event hash chain (read-only).

Usage: verify_integrity.py DB_OR_BACKUP [...]   -- exit 0 ok, 1 tamper evidence, 2 unusable
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis_nexus.event_chain import verify_chain  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    status = 0
    for name in argv:
        path = Path(name)
        try:
            conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            try:
                quick = conn.execute("PRAGMA quick_check").fetchone()[0]
                report = verify_chain(conn)
            finally:
                conn.close()
        except (OSError, sqlite3.Error) as exc:
            print(json.dumps({"file": name, "ok": False, "error": type(exc).__name__}))
            status = max(status, 2)
            continue
        report = {"file": name, "sqlite_quick_check": quick, **report}
        report["ok"] = report["ok"] and quick == "ok"
        print(json.dumps(report, sort_keys=True))
        if not report["ok"]:
            status = max(status, 1)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
