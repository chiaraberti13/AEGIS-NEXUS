# Privacy, retention and credential handling / Privacy, retention e credenziali

## English

Honeypot telemetry may contain IP addresses, usernames, passwords, payloads and identifiers. Treat it as potentially sensitive and hostile at the same time.

Default controls:

- cleartext passwords are **not stored**; AEGIS keeps a SHA-256 fingerprint and length for reuse/correlation studies;
- raw password storage requires the explicit `AEGIS_STORE_CREDENTIAL_SECRETS=true` opt-in and should only be used in a controlled lab with a documented purpose;
- investigation JSON/CSV reports never export cleartext passwords, even when raw storage was explicitly enabled;
- the collector rejects oversized bodies and bounds nested structures and strings;
- hostile values are rendered as text, never as attacker-controlled HTML;
- `AEGIS_RETENTION_DAYS` applies time-based retention continuously while the collector is running;
- `AEGIS_MAX_DB_EVENTS` adds a capacity ceiling so event volume cannot grow the SQLite dataset without bound;
- SQLite secure deletion is enabled and maintenance truncates the WAL after retention/capacity cleanup; backups and storage snapshots still require their own retention policy;
- SOC cases store references to source event/session IDs rather than copies of payloads or credentials, so creating a case does not silently extend telemetry retention;
- case notes and analyst metadata have a lifecycle separate from raw telemetry: define an explicit policy for them and avoid putting secrets or unnecessary personal data in notes;
- restrict dashboard/API access and never publish raw credentials or personal data in reports.

IP geolocation, ASN and reputation information are external context. They can identify VPNs, proxies, NAT gateways, hosting providers or compromised systems rather than the human operator. AEGIS-NEXUS does not infer human identity, threat actor attribution or campaign attribution from these fields.

Before operating an Internet-facing honeypot, define a lawful purpose, access controls, retention period, incident handling process and rules for sharing telemetry that match the jurisdiction in which the system operates.

---

## Italiano

La telemetria di un honeypot può contenere indirizzi IP, username, password, payload e identificatori. Deve essere trattata contemporaneamente come dato potenzialmente sensibile e come input ostile.

Controlli predefiniti:

- le password in chiaro **non vengono archiviate**; AEGIS conserva fingerprint SHA-256 e lunghezza per studi di riuso/correlazione;
- l'archiviazione raw richiede l'opt-in esplicito `AEGIS_STORE_CREDENTIAL_SECRETS=true` e va usata solo in laboratorio controllato con finalità documentata;
- i report investigativi JSON/CSV non esportano mai password in chiaro, anche se la memorizzazione raw è stata abilitata esplicitamente;
- il collector rifiuta body eccessivi e limita profondità, cardinalità e lunghezza delle stringhe;
- i valori ostili vengono renderizzati come testo e mai come HTML controllato dall'attaccante;
- `AEGIS_RETENTION_DAYS` applica la retention temporale in modo continuo mentre il collector è in esecuzione;
- `AEGIS_MAX_DB_EVENTS` impone anche un limite di capacità, evitando che il volume degli eventi faccia crescere indefinitamente il dataset SQLite;
- SQLite utilizza la cancellazione sicura e la manutenzione tronca il WAL dopo i cleanup di retention/capacità; backup e snapshot richiedono comunque una propria policy di conservazione;
- i casi SOC conservano riferimenti agli ID di eventi/sessioni invece di copie di payload o credenziali, quindi creare un caso non estende implicitamente la retention della telemetria;
- note e metadata dei casi hanno un ciclo di vita separato dalla telemetria raw: definisci una policy esplicita e non inserire nelle note segreti o dati personali non necessari;
- limita l'accesso a dashboard/API e non pubblicare credenziali raw o dati personali nei report.

Geolocalizzazione IP, ASN e reputazione sono contesto esterno. Possono indicare VPN, proxy, NAT, provider hosting o sistemi compromessi invece della persona che ha generato il traffico. AEGIS-NEXUS non deduce identità umana, threat actor o campagne da questi campi.

Prima di esporre un honeypot a Internet definisci finalità lecita, controllo accessi, periodo di conservazione, processo di gestione incidenti e regole di condivisione della telemetria coerenti con la giurisdizione in cui il sistema opera.
