"""Evidence-backed MITRE ATT&CK coverage for implemented detection rules.

This module answers a single question: *which ATT&CK techniques are the
implemented detection rules designed to surface?* It is deliberately **not**
attribution and **not** a detection guarantee — it describes rule intent, not a
claim that any particular event maps to a technique.

Every mapping carries an explicit ``rationale`` tied to the rule's deterministic
matcher, honouring the project invariant that MITRE mappings require a rationale
and are never invented. Rules with no defensible, evidence-backed technique
(e.g. a severity-only IDS passthrough) are reported as *unmapped* rather than
being forced onto a technique.
"""

from __future__ import annotations

from typing import Any

from .detection_config import DetectionConfig

COVERAGE_SCHEMA_VERSION = "1.0"

COVERAGE_CAVEAT = (
    "Coverage lists the ATT&CK techniques the implemented detection rules are "
    "designed to surface, each tied to the rule's deterministic matcher. It is "
    "not a detection guarantee and not actor attribution; techniques without an "
    "evidence-backed rule mapping are intentionally omitted."
)


# rule_id -> techniques the rule is designed to surface. Conservative, standard
# ATT&CK correspondences only; each entry states why the rule's matcher is
# evidence for that technique. suricata_high_severity is intentionally absent:
# a severity-only IDS passthrough carries no specific technique on its own.
_RULE_TECHNIQUES: dict[str, tuple[dict[str, str], ...]] = {
    "download_attempt": (
        {
            "technique": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "rationale": "The rule matches captured commands containing a file-download utility or primitive.",
        },
    ),
    "command_staging_detected": (
        {
            "technique": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "rationale": "The rule matches captured commands containing an execution or decoding primitive used during staging.",
        },
    ),
    "honeytoken_reuse": (
        {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Credential Access",
            "rationale": "The rule fires when a planted honeytoken credential is reused, i.e. use of a known valid account.",
        },
    ),
    "multiple_auth_failures": (
        {
            "technique": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "rationale": "The rule matches repeated authentication failures from one source within a time window.",
        },
    ),
    "credential_bruteforce": (
        {
            "technique": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "rationale": "The rule matches many authentication attempts across many usernames within a window.",
        },
    ),
    "credential_reuse": (
        {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Credential Access",
            "rationale": "The rule matches the same credential fingerprint observed across multiple sources.",
        },
    ),
    "web_scanning": (
        {
            "technique": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
            "rationale": "The rule matches many distinct web paths probed from one source within a window.",
        },
    ),
    "path_traversal_sequence": (
        {
            "technique": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "rationale": "The rule matches repeated path-traversal sequences probing filesystem paths.",
        },
    ),
    "rapid_port_sequence": (
        {
            "technique": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "rationale": "The rule matches rapid sequential probing across destination ports from one source.",
        },
    ),
    "recon_burst": (
        {
            "technique": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
            "rationale": "The rule matches a burst of reconnaissance-style events across services/ports from one source.",
        },
    ),
}


def mitre_coverage(config: DetectionConfig) -> dict[str, Any]:
    """Build the ATT&CK coverage view for the implemented rules in ``config``.

    Only rule ids present in the configuration are considered "implemented".
    Each technique records the contributing rules, whether they are currently
    enabled, and the per-rule rationale. Rules without a mapping are listed
    under ``unmapped_rules`` so the view never hides a gap.
    """
    techniques: dict[str, dict[str, Any]] = {}
    unmapped: list[dict[str, str]] = []

    for rule_id in sorted(config.rules):
        mappings = _RULE_TECHNIQUES.get(rule_id)
        if not mappings:
            unmapped.append(
                {
                    "rule_id": rule_id,
                    "reason": "no evidence-backed ATT&CK technique asserted for this rule",
                }
            )
            continue
        enabled = config.enabled(rule_id)
        for mapping in mappings:
            entry = techniques.setdefault(
                mapping["technique"],
                {
                    "technique": mapping["technique"],
                    "name": mapping["name"],
                    "tactic": mapping["tactic"],
                    "enabled": False,
                    "rules": [],
                },
            )
            entry["rules"].append(
                {
                    "rule_id": rule_id,
                    "enabled": enabled,
                    "rationale": mapping["rationale"],
                }
            )
            if enabled:
                entry["enabled"] = True

    ordered = sorted(techniques.values(), key=lambda item: item["technique"])
    for entry in ordered:
        entry["rules"].sort(key=lambda rule: rule["rule_id"])

    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "caveat": COVERAGE_CAVEAT,
        "technique_count": len(ordered),
        "enabled_technique_count": sum(1 for entry in ordered if entry["enabled"]),
        "techniques": ordered,
        "unmapped_rules": unmapped,
    }
