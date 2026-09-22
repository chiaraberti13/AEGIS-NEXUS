<p align="center"><a href="#-english">🇬🇧 English</a> · <a href="#-italiano">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/security-hostile--input%20model-22D3EE?style=flat-square" alt="Hostile input model">
  <img src="https://img.shields.io/badge/disclosure-private-F2C94C?style=flat-square" alt="Private disclosure">
</p>

<p align="center"><a href="README.md">Project README</a> · <a href="LICENSE">MIT Licence</a> · <a href="docs/THREAT_MODEL.md">Threat model</a></p>

---

## 🇬🇧 English

### Supported versions
Security fixes target the latest version on the default branch.

### Reporting a vulnerability
Report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/chiaraberti13/AEGIS-NEXUS/security/advisories/new). Do not publish unpatched vulnerabilities, captured credentials, real attacker payloads or personal data in issues.

Include the affected commit, component, impact, reproducible steps, sanitized telemetry and possible mitigations.

### Security model
Every byte collected by a honeypot is treated as hostile. Event ingestion fails closed when no valid ingest key is configured; sensor identity can be bound to per-sensor keys. The collector bounds request size, string length, nesting and list cardinality; it never needs to execute captured payloads. Cleartext passwords are redacted by default. The Docker runtime is non-root, drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem and exposes the operator console on localhost only. Sensors have bounded concurrent connections and dedicated management networks to the collector. Continuous retention and a maximum event count bound persistent storage growth.

Deploy only on infrastructure you own or are explicitly authorized to monitor. Keep honeypots separated from production networks and do not use captured systems or data to counter-attack third parties.

---

## 🇮🇹 Italiano

### Versioni supportate
Le correzioni di sicurezza riguardano la versione più recente del branch predefinito.

### Segnalazione di una vulnerabilità
Segnala privatamente le vulnerabilità sospette tramite [GitHub Security Advisories](https://github.com/chiaraberti13/AEGIS-NEXUS/security/advisories/new). Non pubblicare in issue vulnerabilità non corrette, credenziali raccolte, payload reali o dati personali.

Indica commit e componente interessati, impatto, passaggi riproducibili, telemetria sanitizzata e possibili mitigazioni.

### Modello di sicurezza
Ogni byte raccolto da un honeypot viene trattato come input ostile. L'ingestione fallisce in modo chiuso quando non è configurata una chiave valida; l'identità dei sensori può essere associata a chiavi dedicate per singolo sensore. Il collector limita dimensione delle richieste, lunghezza delle stringhe, profondità e cardinalità delle strutture; non deve mai eseguire i payload catturati. Le password in chiaro vengono redatte per impostazione predefinita. Il runtime Docker usa un utente non-root, rimuove le capability Linux, abilita `no-new-privileges`, usa un filesystem root in sola lettura ed espone la console operatore solo su localhost. I sensori hanno un limite alle connessioni concorrenti e reti management dedicate verso il collector. Retention continua e limite massimo di eventi contengono la crescita dello storage persistente.

Distribuisci il progetto esclusivamente su infrastrutture di tua proprietà o per le quali possiedi autorizzazione esplicita. Mantieni gli honeypot separati dalle reti di produzione e non usare sistemi o dati raccolti per contro-attaccare terze parti.
