"""Relationship-graph projection for a session bundle.

Extracted from ``store.py`` as the first incremental step of the Cycle I
storage split (ADR 0003). The function is pure: it depends only on an
already-resolved session bundle, a node cap and a credential-secret summary
callable, so it has no SQLite/``Store`` coupling and is unit-testable on its
own. ``Store.relations`` delegates here, keeping the public API unchanged
(guarded by ``tests/test_api_contract.py``).

The graph preserves the evidence-first provenance split: every node carries a
``provenance`` of ``observed`` / ``enrichment`` / ``derived``, and the classes
are never collapsed.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Callable


def build_relation_graph(
    bundle: dict[str, Any],
    *,
    max_nodes: int,
    credential_secret_summary: Callable[[dict[str, Any]], dict[str, Any] | None],
) -> dict[str, Any]:
    """Build the node/edge relationship graph for a resolved session bundle.

    ``bundle`` is the output of ``Store.get_session``; ``max_nodes`` bounds the
    graph (hostile input is guilty until bounded); ``credential_secret_summary``
    is ``Store._credential_secret_summary`` (redacted fingerprint, never the
    cleartext secret).
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    graph_truncated = False

    def add(kind: str, value: Any, provenance: str, metadata: dict[str, Any] | None = None) -> str | None:
        nonlocal graph_truncated
        if value in (None, ""):
            return None
        label = str(value)
        digest = hashlib.sha256(f"{kind}\0{label}".encode("utf-8", "replace")).hexdigest()[:20]
        node_id = f"{kind}:{digest}"
        if node_id not in nodes and len(nodes) >= max_nodes:
            graph_truncated = True
            return None
        node: dict[str, Any] = {
            "id": node_id,
            "kind": kind,
            "label": label[:180],
            "provenance": provenance,
        }
        if metadata:
            node["metadata"] = deepcopy(metadata)
        nodes[node_id] = node
        return node_id

    for event in bundle["events"]:
        event_node = add("event", event["id"], "observed")
        if event_node is None and graph_truncated:
            break
        summary = bundle.get("summary", {})
        session_node = add("session", event["session_id"], "derived", {
            "correlation": deepcopy(summary.get("correlation") or {
                "method": summary.get("correlation_method", "temporal_fallback"),
                "strength": "heuristic",
                "basis": [],
            })
        })
        ip_node = add("ip", event.get("source_ip"), "observed")
        asn_node = add("asn", event.get("asn"), "enrichment")
        country_node = add("country", event.get("country"), "enrichment")
        port_node = add("port", event.get("destination_port"), "observed")
        protocol_node = add("protocol", event.get("protocol"), "observed")
        service_node = add("service", event.get("service"), "observed")
        honeypot_node = add("honeypot", event.get("honeypot"), "observed")
        credential = event["observed"].get("credential")
        credential = credential if isinstance(credential, dict) else {}
        user_node = add("credential", credential.get("username"), "observed")
        secret_node = None
        secret = credential_secret_summary(credential)
        if secret:
            secret_node = add(
                "credential_secret_fingerprint",
                secret["label"],
                "derived",
                {
                    "algorithm": "sha256",
                    "password_length": secret["length"],
                    "complete": secret["complete"],
                    "fingerprint_provenance": secret["provenance"],
                },
            )
        command_node = add("command", event["observed"].get("command"), "observed")
        payload_node = add("payload", event["observed"].get("payload"), "observed")

        alert = event["observed"].get("alert")
        alert = alert if isinstance(alert, dict) else {}
        alert_node = add("ids", alert.get("signature"), "observed", {
            "category": alert.get("category"),
            "signature_id": alert.get("signature_id"),
        })

        for target, relation in [
            (session_node, "belongs_to"),
            (ip_node, "source"),
            (asn_node, "enriched_asn"),
            (country_node, "enriched_country"),
            (port_node, "targets_port"),
            (protocol_node, "uses_protocol"),
            (service_node, "targets_service"),
            (honeypot_node, "observed_by"),
            (user_node, "uses_username"),
            (secret_node, "credential_secret_fingerprint"),
            (command_node, "observed_command"),
            (payload_node, "observed_payload"),
            (alert_node, "ids_alert"),
        ]:
            if event_node and target:
                edges.add((event_node, target, relation))

        for item in event["derived"].get("mitre", []) or []:
            if not isinstance(item, dict):
                continue
            mitre_node = add("mitre", item.get("technique_id"), "derived", {
                "rationale": item.get("rationale"),
                "evidence": item.get("evidence"),
            })
            if event_node and mitre_node:
                edges.add((event_node, mitre_node, "mapped_with_evidence"))

        for item in event["derived"].get("cve", []) or []:
            if not isinstance(item, dict):
                continue
            cve_node = add("cve", item.get("cve_id"), "derived", {
                "rationale": item.get("rationale"),
                "evidence": item.get("evidence"),
            })
            if event_node and cve_node:
                edges.add((event_node, cve_node, "correlated_with_evidence"))

        for ioc in event["derived"].get("ioc", []) or []:
            if not isinstance(ioc, dict):
                continue
            ioc_type = ioc.get("type")
            ioc_value = ioc.get("value")
            ioc_node = add("ioc", ioc_value, "derived", {
                "type": ioc_type,
                "evidence": ioc.get("evidence"),
                "classification": ioc.get("classification"),
            })
            if event_node and ioc_node:
                edges.add((event_node, ioc_node, "derived_ioc"))

        threat_context = (event.get("enrichment") or {}).get("threat_context")
        if isinstance(threat_context, dict):
            source = threat_context.get("source")
            raw_data = threat_context.get("data")
            data = raw_data if isinstance(raw_data, dict) else {}
            for match in (data.get("matches") or [])[:16]:
                if not isinstance(match, dict):
                    continue
                kind = match.get("type")
                value = match.get("value")
                label = f"{kind}: {value}" if kind and value not in (None, "") else value
                ti_node = add("threat_intel", label, "enrichment", {
                    "source": source,
                    "confidence": match.get("confidence"),
                    "labels": match.get("labels"),
                    "reference": match.get("reference"),
                    "evidence": match.get("evidence"),
                })
                if event_node and ti_node:
                    edges.add((event_node, ti_node, "external_threat_context"))

    graph_analysis = dict(bundle.get("analysis", {}))
    graph_analysis.update({
        "graph_truncated": graph_truncated,
        "graph_node_limit": max_nodes,
        "graph_nodes_returned": len(nodes),
        "graph_edges_returned": len(edges),
    })
    return {
        "analysis": graph_analysis,
        "nodes": list(nodes.values()),
        "edges": [
            {
                "source": source,
                "target": target,
                "relation": relation,
                "provenance": (nodes.get(target) or {}).get("provenance", "observed"),
            }
            for source, target, relation in sorted(edges)
        ],
        "provenance": {
            "observed": "direct sensor or IDS telemetry",
            "enrichment": "external or operator-supplied context",
            "derived": "deterministic correlation or evidence-backed derivation",
        },
    }
