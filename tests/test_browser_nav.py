from __future__ import annotations

import shutil
import subprocess
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from aegis_nexus.app import create_app

_SCRIPT = Path(__file__).resolve().parent / "browser" / "nav_smoke.cjs"


def _node_playwright_available() -> bool:
    if shutil.which("node") is None:
        return False
    probe = subprocess.run(["node", "-e", "require('playwright')"], capture_output=True)
    return probe.returncode == 0


@pytest.mark.skipif(not _node_playwright_available(), reason="node + playwright not available")
def test_every_view_activates_without_uncaught_js_error(tmp_path):
    # Guards the app.js -> ES-module split (ADR 0003): clicking through every nav
    # view must not raise an uncaught JS error (e.g. a missing module import or
    # an undefined reference after a view is extracted).
    app = create_app({
        "TESTING": True,  # operator endpoints open in test/lab mode (no gate)
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
    })
    # Seed one event so data-backed views have something to render.
    res = app.test_client().post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": "whoami"},
        },
    )
    assert res.status_code == 201

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            ["node", str(_SCRIPT), f"http://127.0.0.1:{port}/"],
            capture_output=True, text=True, timeout=120,
        )
    finally:
        server.shutdown()
    assert result.returncode == 0, f"browser nav smoke failed:\n{result.stdout}\n{result.stderr}"
