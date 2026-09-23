from __future__ import annotations

import json
import os
import time
import urllib.request
from datetime import datetime, timezone

from aegis_nexus.security import sign_payload


def main() -> None:
    url = os.getenv("AEGIS_URL", "http://127.0.0.1:8600/api/v1/events")
    key = (
        os.getenv("AEGIS_SENSOR_API_KEY")
        or os.getenv("AEGIS_SSH_SENSOR_API_KEY")
        or os.getenv("AEGIS_INGEST_API_KEY", "")
    )
    if not key:
        raise SystemExit("Set AEGIS_SENSOR_API_KEY (or AEGIS_SSH_SENSOR_API_KEY) before running the smoke test")
    sensor_id = os.getenv("AEGIS_SMOKE_SENSOR_ID", "ssh-decoy-01")
    destination_port = int(os.getenv("AEGIS_SMOKE_DESTINATION_PORT", "2222"))

    samples = [
        {
            "honeypot": sensor_id,
            "event_type": "credential",
            "severity": "medium",
            "observed": {
                "source_ip": "203.0.113.10",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": destination_port,
                "credential": {"username": "root", "password": "lab-only"},
            },
        },
        {
            "honeypot": sensor_id,
            "event_type": "command",
            "severity": "medium",
            "observed": {
                "source_ip": "203.0.113.10",
                "service": "ssh",
                "protocol": "tcp",
                "destination_port": destination_port,
                "command": "uname -a",
            },
            "derived": {
                "mitre": [{
                    "technique_id": "T1059",
                    "rationale": "Command execution was present in the simulated observation",
                    "evidence": ["observed.command"],
                }]
            },
        },
    ]

    for sample in samples:
        sample["timestamp"] = datetime.now(timezone.utc).isoformat()
        sample.setdefault("derived", {})["data_mode"] = "simulation"
        body = json.dumps(sample, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        signed_at = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "X-Aegis-Key": key,
            "X-Aegis-Sensor": sensor_id,
            "X-Aegis-Timestamp": signed_at,
            "X-Aegis-Signature": sign_payload(key, signed_at, body),
        }
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            print(response.read().decode())


if __name__ == "__main__":
    main()
