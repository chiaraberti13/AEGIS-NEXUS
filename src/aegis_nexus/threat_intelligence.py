from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ThreatIntelligenceProvider(ABC):
    """Contract for evidence-preserving threat-intelligence enrichment providers."""

    provider_id: str
    network_requests: bool

    @abstractmethod
    def status(self) -> dict[str, Any]:
        """Return bounded operator-visible provider health/configuration metadata."""
        raise NotImplementedError

    @abstractmethod
    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return an enriched event without mutating the caller's event."""
        raise NotImplementedError

    def close(self) -> None:
        """Release optional provider resources."""
        return None


def validate_provider(provider: ThreatIntelligenceProvider) -> None:
    provider_id = str(getattr(provider, "provider_id", "") or "").strip()
    if not provider_id or len(provider_id) > 96:
        raise ValueError("threat intelligence provider requires a bounded provider_id")
    if not isinstance(getattr(provider, "network_requests", None), bool):
        raise ValueError("threat intelligence provider must declare network_requests")
    if not callable(getattr(provider, "status", None)):
        raise ValueError("threat intelligence provider requires status()")
    if not callable(getattr(provider, "enrich", None)):
        raise ValueError("threat intelligence provider requires enrich()")
