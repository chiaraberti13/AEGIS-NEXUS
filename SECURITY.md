# Security Policy

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

## English

### Supported versions
Security fixes target the latest revision on the repository's default branch unless a release is explicitly documented as supported. Older commits, forks, unofficial builds and locally modified deployments are not supported by default.

### Scope
This policy covers the collector, decoys, SOC console, ingestion paths, container/deployment configuration, evidence handling and bundled tooling. Reports involving sensor authentication, isolation bypass, unauthorized data exposure, command execution, SSRF, injection, provenance corruption or secret leakage are especially important.

### Reporting a vulnerability
Do **not** open a public issue for an unpatched vulnerability. Use GitHub's private security reporting / Security Advisories for this repository when available. Include the affected version or commit, impact, reproducible steps or a minimal proof of concept, environmental assumptions, and possible mitigations. Remove credentials, personal data and unrelated confidential information from evidence.

### Responsible testing
Test only systems, devices, data and signals you own or are explicitly authorized to assess. Do not perform denial-of-service testing, destructive actions, persistence, social engineering, unauthorized interception, or access to third-party data. A repository's educational or security purpose is not authorization to test external infrastructure.

### Secrets and data
Never commit real secrets, tokens, credentials, private keys, customer/production data or sensitive exports. Rotate any secret that may have been exposed and remove it from active history where appropriate.

### Dependency and supply-chain security
Review dependency changes, lockfiles, third-party source, build scripts and CI permissions. Prefer pinned/reproducible dependencies and the repository's existing automated checks. For Internet-facing honeypot deployments, verify network segmentation, management-network isolation, egress controls and retention settings before exposure.

### Disclosure
Allow reasonable time for investigation and remediation before public disclosure. Coordinate publication of technical details when premature disclosure could increase risk.

---

## Italiano

### Versioni supportate
Le correzioni di sicurezza riguardano la revisione più recente del branch predefinito, salvo release esplicitamente dichiarate supportate. Commit precedenti, fork, build non ufficiali e installazioni modificate localmente non sono supportati per impostazione predefinita.

### Ambito
This policy covers the collector, decoys, SOC console, ingestion paths, container/deployment configuration, evidence handling and bundled tooling. Reports involving sensor authentication, isolation bypass, unauthorized data exposure, command execution, SSRF, injection, provenance corruption or secret leakage are especially important.

### Segnalazione di una vulnerabilità
Non aprire issue pubbliche per vulnerabilità non corrette. Usa la segnalazione privata / GitHub Security Advisories del repository quando disponibile. Includi versione o commit interessato, impatto, passaggi riproducibili o PoC minimo, assunzioni ambientali e possibili mitigazioni. Rimuovi credenziali, dati personali e informazioni riservate non necessarie dalle evidenze.

### Test responsabili
Esegui test solo su sistemi, dispositivi, dati e segnali propri o esplicitamente autorizzati. Sono esclusi DoS, azioni distruttive, persistenza, social engineering, intercettazione non autorizzata e accesso a dati di terzi. La finalità didattica o di sicurezza del repository non costituisce autorizzazione verso infrastrutture esterne.

### Segreti e dati
Non committare segreti reali, token, credenziali, chiavi private, dati di clienti/produzione o export sensibili. Ruota qualsiasi segreto potenzialmente esposto e rimuovilo dalla cronologia attiva quando opportuno.

### Dipendenze e supply chain
Valuta modifiche alle dipendenze, lockfile, sorgenti di terze parti, script di build e permessi CI. Preferisci dipendenze riproducibili/pinnate e i controlli automatici già previsti. For Internet-facing honeypot deployments, verify network segmentation, management-network isolation, egress controls and retention settings before exposure.

### Divulgazione
Concedi un tempo ragionevole per analisi e correzione prima della divulgazione pubblica e coordina la pubblicazione dei dettagli quando una disclosure prematura aumenterebbe il rischio.
