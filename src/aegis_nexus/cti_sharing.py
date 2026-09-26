from __future__ import annotations

import uuid
from typing import Any

TLP_V2_LABELS = {
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
}

_STIX_TLP = {
    "TLP:CLEAR": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    },
    "TLP:GREEN": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "TLP:AMBER": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "TLP:AMBER+STRICT": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "TLP:RED": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}

_POLICY = {
    "TLP:CLEAR": "FIRST TLP 2.0 TLP:CLEAR: public sharing is permitted, subject to applicable rules and copyright.",
    "TLP:GREEN": "FIRST TLP 2.0 TLP:GREEN: share within the community; do not publish on publicly accessible channels.",
    "TLP:AMBER": "FIRST TLP 2.0 TLP:AMBER: share on a need-to-know basis within the organization and its clients.",
    "TLP:AMBER+STRICT": "FIRST TLP 2.0 TLP:AMBER+STRICT: share on a need-to-know basis within the recipient organization only.",
    "TLP:RED": "FIRST TLP 2.0 TLP:RED: for individual recipients only; no further disclosure.",
}

_STATEMENT_NAMESPACE = uuid.UUID("b8c48db9-8fc7-55e6-b7ab-bcc81851db4e")


def normalize_tlp(value: str) -> str:
    label = str(value or "").strip().upper()
    if label not in TLP_V2_LABELS:
        raise ValueError("invalid_tlp_v2_label")
    return label


def stix_sharing_markings(tlp: str) -> tuple[list[dict[str, Any]], list[str]]:
    label = normalize_tlp(tlp)
    standard = dict(_STIX_TLP[label])
    statement_id = "marking-definition--" + str(uuid.uuid5(_STATEMENT_NAMESPACE, label))
    statement = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": statement_id,
        "created": "2026-09-26T00:00:00.000Z",
        "definition_type": "statement",
        "name": f"AEGIS FIRST TLP 2.0 {label}",
        "definition": {"statement": _POLICY[label]},
    }
    return [standard, statement], [standard["id"], statement_id]
