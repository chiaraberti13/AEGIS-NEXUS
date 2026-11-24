from __future__ import annotations

import shutil
import subprocess
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from aegis_nexus.app import create_app

_SCRIPT = Path(__file__).resolve().parent / "browser" / "xss_smoke.cjs"
_HOSTILE_COMMAND = '<script>window.__xss__=1</script><img src=x onerror="window.__xss__=1">'


def _node_playwright_available() -> bool:
    if shutil.which("node") is None:
        return False
    probe = subprocess.run(["node", "-e", "require('playwright')"], capture_output=True)
    return probe.returncode == 0


@pytest.mark.skipif(not _node_playwright_available(), reason="node + playwright not available")
def test_console_renders_hostile_event_without_xss(tmp_path):
    app = create_app({
        "TESTING": True,  # operator endpoints open in test/lab mode (no gate)
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "sensor-secret",
    })
    # Ingest an event whose captured command carries hostile markup.
    res = app.test_client().post(
        "/api/v1/events",
        headers={"X-Aegis-Key": "sensor-secret"},
        json={
            "honeypot": "ssh-1",
            "event_type": "command",
            "observed": {"source_ip": "203.0.113.5", "service": "ssh", "protocol": "tcp",
                         "destination_port": 22, "command": _HOSTILE_COMMAND},
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
    assert result.returncode == 0, f"browser smoke failed:\n{result.stdout}\n{result.stderr}"
