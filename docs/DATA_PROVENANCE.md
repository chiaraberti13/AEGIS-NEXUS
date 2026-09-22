# Data provenance model / Modello di provenienza dati

AEGIS-NEXUS keeps four classes separate in every event:

- `observed`: values captured directly by a sensor or honeypot.
- `enrichment`: external context; every block requires `source` and `observed_at`.
- `derived`: deterministic or analyst-produced values derived from evidence. MITRE/CVE entries require both `rationale` and `evidence`.
- `hypotheses`: explicitly non-factual analytical possibilities.

The UI and API must never collapse these classes into a single “truth” field. IP geolocation, ASN ownership and threat-intelligence reputation are contextual data, not attacker identity.

---

AEGIS-NEXUS mantiene separate quattro classi in ogni evento:

- `observed`: valori catturati direttamente da un sensore o honeypot.
- `enrichment`: contesto esterno; ogni blocco richiede `source` e `observed_at`.
- `derived`: valori deterministici o prodotti dall'analista a partire da evidenze. Le voci MITRE/CVE richiedono `rationale` ed `evidence`.
- `hypotheses`: possibilità analitiche esplicitamente non fattuali.

UI e API non devono mai fondere queste classi in un unico campo di “verità”. Geolocalizzazione IP, proprietà ASN e reputazione Threat Intelligence sono contesto, non identità dell'attaccante.
