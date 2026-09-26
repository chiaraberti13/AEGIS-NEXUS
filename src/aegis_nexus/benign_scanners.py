from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class BenignScannerContext:
    """Offline operator context for known scanner networks; never a suppression list."""

    def __init__(self, path: str = "", *, max_bytes: int = 1024 * 1024, max_entries: int = 10_000):
        self.path = Path(path).expanduser() if path else None
        self.max_bytes = max(1024, min(int(max_bytes), 10 * 1024 * 1024))
        self.max_entries = max(1, min(int(max_entries), 100_000))
        self.source: str | None = None
        self.loaded_at: str | None = None
        self.error: str | None = None
        self.entries: list[tuple[Any, dict[str, Any]]] = []
        if self.path:
            self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
            if len(raw) > self.max_bytes:
                raise ValueError("benign_scanner_file_too_large")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
                raise ValueError("invalid_benign_scanner_file")
            if len(payload["entries"]) > self.max_entries:
                raise ValueError("too_many_benign_scanner_entries")
            entries = []
            for item in payload["entries"]:
                if not isinstance(item, dict):
                    continue
                cidr = str(item.get("cidr") or "")[:128]
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                metadata = {"cidr": str(network)}
                for key, limit in (("name", 128), ("description", 256), ("reference", 512)):
                    if item.get(key) not in (None, ""):
                        metadata[key] = str(item[key]).strip()[:limit]
                entries.append((network, metadata))
            self.entries = entries
            self.source = str(payload.get("source") or f"benign-scanner-list:{self.path.name}")[:256]
            self.loaded_at = datetime.now(timezone.utc).isoformat()
            self.error = None
        except Exception as exc:
            self.entries = []
            self.loaded_at = None
            self.error = str(exc)[:160] if isinstance(exc, ValueError) else type(exc).__name__

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.path is not None,
            "ready": self.path is not None and self.error is None and self.loaded_at is not None,
            "source": self.source,
            "loaded_at": self.loaded_at,
            "entries": len(self.entries),
            "error": self.error,
            "suppression": False,
        }

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        source_ip = (event.get("observed") or {}).get("source_ip")
        if not source_ip or not self.entries:
            return event
        try:
            address = ipaddress.ip_address(str(source_ip))
        except ValueError:
            return event
        matches = [
            deepcopy(metadata)
            for network, metadata in self.entries
            if address.version == network.version and address in network
        ][:8]
        if not matches:
            return event
        result = deepcopy(event)
        result.setdefault("enrichment", {})["benign_scanner_context"] = {
            "source": self.source,
            "retrieved_at": self.loaded_at,
            "match_policy": "network_membership",
            "context_only": True,
            "suppression": False,
            "matches": matches,
        }
        return result
