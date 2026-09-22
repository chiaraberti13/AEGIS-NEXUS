from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone

URL = os.getenv("AEGIS_URL", "http://127.0.0.1:8600/api/v1/events")
KEY = os.getenv("AEGIS_INGEST_API_KEY", "")

samples = [
    {"honeypot":"ssh-lab","event_type":"credential","severity":"medium","observed":{"source_ip":"203.0.113.10","service":"ssh","protocol":"tcp","destination_port":22,"credential":{"username":"root","password":"lab-only"}}},
    {"honeypot":"ssh-lab","event_type":"command","severity":"medium","observed":{"source_ip":"203.0.113.10","service":"ssh","protocol":"tcp","destination_port":22,"command":"uname -a"},"derived":{"mitre":[{"technique_id":"T1059","rationale":"Command execution was present in the simulated observation","evidence":["observed.command"]}]}},
]

for sample in samples:
    sample["timestamp"] = datetime.now(timezone.utc).isoformat()
    sample.setdefault("derived", {})["data_mode"] = "simulation"
    data = json.dumps(sample).encode()
    request = urllib.request.Request(URL, data=data, headers={"Content-Type":"application/json","X-Aegis-Key":KEY}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        print(response.read().decode())
