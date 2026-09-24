from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence

FINGERPRINT_SCHEMA_VERSION = "1.0"
ALLOWED_FINGERPRINT_KINDS = {
    "tls_client",
    "tls_server",
    "application",
    "tcp_stack_hint",
}


@dataclass(frozen=True)
class FingerprintFinding:
    """Evidence-backed passive fingerprint result.

    A finding is not an OS, actor or identity attribution. Providers must expose
    the exact evidence paths used so callers can keep hints separate from facts.
    """

    provider: str
    kind: str
    fingerprint: str
    evidence: tuple[str, ...]
    confidence: float | None = None
    label: str | None = None

    def as_dict(self) -> dict[str, Any]:
        if self.kind not in ALLOWED_FINGERPRINT_KINDS:
            raise ValueError("unsupported fingerprint kind")
        if not self.provider or not self.fingerprint or not self.evidence:
            raise ValueError("fingerprint finding requires provider, fingerprint and evidence")
        if self.confidence is not None and not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("fingerprint confidence must be between 0 and 1")
        result: dict[str, Any] = {
            "schema_version": FINGERPRINT_SCHEMA_VERSION,
            "provider": self.provider[:128],
            "kind": self.kind,
            "fingerprint": self.fingerprint[:512],
            "evidence": [str(path)[:256] for path in self.evidence[:32]],
            "attribution": False,
        }
        if self.confidence is not None:
            result["confidence"] = round(float(self.confidence), 4)
        if self.label:
            result["label"] = self.label[:256]
        return result


class PassiveFingerprintProvider(Protocol):
    name: str

    def analyze(self, network: dict[str, Any]) -> Sequence[FingerprintFinding]:
        """Return evidence-backed fingerprints from already observed network metadata."""


class NullPassiveFingerprintProvider:
    name = "disabled"

    def analyze(self, network: dict[str, Any]) -> Sequence[FingerprintFinding]:
        return ()
