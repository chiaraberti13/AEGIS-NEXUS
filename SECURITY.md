# Security Policy

## Supported versions
Security fixes target the latest revision on the repository's default branch unless a release is explicitly documented as supported. Older commits, forks, unofficial builds and locally modified deployments are not supported by default.

## Scope
This policy covers the collector, decoys, SOC console, ingestion paths, container/deployment configuration, evidence handling and bundled tooling. Reports involving sensor authentication, isolation bypass, unauthorized data exposure, command execution, SSRF, injection, provenance corruption or secret leakage are especially important.

## Reporting a vulnerability
Do **not** open a public issue for an unpatched vulnerability. Use GitHub's private security reporting / Security Advisories for this repository when available. Include the affected version or commit, impact, reproducible steps or a minimal proof of concept, environmental assumptions, and possible mitigations. Remove credentials, personal data and unrelated confidential information from evidence.

## Responsible testing
Test only systems, devices, data and signals you own or are explicitly authorized to assess. Do not perform denial-of-service testing, destructive actions, persistence, social engineering, unauthorized interception, or access to third-party data. A repository's educational or security purpose is not authorization to test external infrastructure.

## Secrets and data
Never commit real secrets, tokens, credentials, private keys, customer/production data or sensitive exports. Rotate any secret that may have been exposed and remove it from active history where appropriate.

## Dependency and supply-chain security
Review dependency changes, lockfiles, third-party source, build scripts and CI permissions. Prefer pinned/reproducible dependencies and the repository's existing automated checks. For Internet-facing honeypot deployments, verify network segmentation, management-network isolation, egress controls and retention settings before exposure.

## Disclosure
Allow reasonable time for investigation and remediation before public disclosure. Coordinate publication of technical details when premature disclosure could increase risk.

---

## Private reporting process

Use **Report a vulnerability** in the repository Security tab if private reporting is available. Otherwise use a verified private contact published by the repository owner. If no private contact is available, open a public issue asking only for a private contact, without vulnerability details. Do not publish exploit details, credentials, personal data or sensitive logs in public issues.

Include the affected revision, environment, impact and minimal synthetic reproduction. Coordinate disclosure with the maintainer. Acknowledgement and remediation depend on availability and severity; no fixed response deadline is guaranteed.
