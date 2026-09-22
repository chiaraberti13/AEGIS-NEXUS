from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from aegis_nexus.security import sign_payload


def send_event(url: str, sensor: str, secret: str, event: dict, timeout: float) -> int:
    body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
    timestamp = str(int(time.time()))
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Aegis-Key": secret,
            "X-Aegis-Sensor": sensor,
            "X-Aegis-Timestamp": timestamp,
            "X-Aegis-Signature": sign_payload(secret, timestamp, body),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status


def main() -> None:
    parser = argparse.ArgumentParser(description="Forward Suricata EVE JSON lines to AEGIS-NEXUS with signed transport.")
    parser.add_argument("--file", help="EVE JSON file. Reads stdin when omitted.")
    parser.add_argument("--url", default=os.getenv("AEGIS_SURICATA_URL", "http://127.0.0.1:8600/api/v1/integrations/suricata/eve"))
    parser.add_argument("--sensor", default=os.getenv("AEGIS_SURICATA_SENSOR_ID", "suricata-01"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AEGIS_SENSOR_TIMEOUT", "2.0")))
    args = parser.parse_args()

    secret = os.getenv("AEGIS_SENSOR_API_KEY") or os.getenv("AEGIS_INGEST_API_KEY", "")
    if not secret:
        raise SystemExit("AEGIS_SENSOR_API_KEY or AEGIS_INGEST_API_KEY must be set")

    stream = open(args.file, "r", encoding="utf-8") if args.file else sys.stdin
    sent = failed = 0
    try:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event is not a JSON object")
                status = send_event(args.url, args.sensor, secret, event, args.timeout)
                if 200 <= status < 300:
                    sent += 1
                else:
                    failed += 1
                    print(f"line {line_number}: HTTP {status}", file=sys.stderr)
            except (json.JSONDecodeError, ValueError, urllib.error.URLError, TimeoutError, OSError) as exc:
                failed += 1
                print(f"line {line_number}: {type(exc).__name__}", file=sys.stderr)
    finally:
        if args.file:
            stream.close()

    print(f"sent={sent} failed={failed}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
