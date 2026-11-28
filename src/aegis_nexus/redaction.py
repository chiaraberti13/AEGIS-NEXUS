"""Report redaction profiles.

`internal` returns the report unchanged. `shareable` masks structured network
identifiers and removes operator/analyst identities so a report can leave the
trust boundary with less personal data. It is deliberately conservative and
honest: it redacts *structured fields* only and never pretends to be full
anonymization — free-text analyst fields (summary, notes, conclusion,
hypotheses) and attacker-embedded identifiers inside commands/payloads are left
intact for the operator to review before sharing.
"""

from __future__ import annotations

import ipaddress
from copy import deepcopy
from typing import Any

REDACTION_PROFILES = {"internal", "shareable"}

# Structured dict keys masked/removed under the shareable profile, wherever they
# appear in the report tree.
_MASK_IP_KEYS = {"source_ip"}
_MASK_IP_LIST_KEYS = {"source_ips"}
_REMOVE_IDENTITY_KEYS = {"username", "operator", "owner"}

_REDACTED_USERNAME = "[redacted-username]"
_REDACTED_OPERATOR = "[redacted-operator]"
_REDACTED_IP = "[redacted-ip]"


def mask_ip(value: Any) -> str:
    """Mask an IP to its network prefix (/24 for IPv4, /48 for IPv6)."""
    text = str(value or "").strip()
    if not text:
        return _REDACTED_IP
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return _REDACTED_IP
    prefix = 24 if address.version == 4 else 48
    network = ipaddress.ip_network(f"{text}/{prefix}", strict=False)
    return str(network)


def _redact_in_place(node: Any) -> None:
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if key in _MASK_IP_KEYS and isinstance(value, str) and value:
                node[key] = mask_ip(value)
            elif key in _MASK_IP_LIST_KEYS and isinstance(value, list):
                node[key] = sorted({mask_ip(entry) for entry in value if isinstance(entry, str) and entry})
            elif key in _REMOVE_IDENTITY_KEYS and isinstance(value, str) and value:
                node[key] = _REDACTED_OPERATOR if key in {"operator", "owner"} else _REDACTED_USERNAME
            else:
                _redact_in_place(value)
    elif isinstance(node, list):
        for item in node:
            _redact_in_place(item)


_REDACTION_NOTES = {
    "en": (
        "Shareable profile: source IPs are masked to their network prefix and "
        "usernames/operator identities are removed. This is not full "
        "anonymization — review free-text fields and command/payload evidence "
        "for embedded identifiers before sharing."
    ),
    "it": (
        "Il profilo maschera gli IP sorgente al prefisso di rete e rimuove nomi "
        "utente e identità degli operatori. L'anonimizzazione è parziale. Prima "
        "di condividere il report, verifica eventuali identificatori presenti "
        "nei campi a testo libero, nei comandi e nei payload."
    ),
}


def redact_report(
    report: dict[str, Any], profile: str = "internal", *, lang: str = "en",
) -> dict[str, Any]:
    """Return a copy of the report according to a supported profile."""
    if profile not in REDACTION_PROFILES:
        raise ValueError("Unknown report redaction profile")
    result = deepcopy(report)
    result["redaction_profile"] = profile
    if profile == "shareable":
        _redact_in_place(result)
        result["redaction_note"] = _REDACTION_NOTES["it" if lang.lower().startswith("it") else "en"]
    return result
