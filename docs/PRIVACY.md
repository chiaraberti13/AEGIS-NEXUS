# Privacy, retention and credential handling / Privacy, retention e credenziali

## English

Honeypot telemetry may contain IP addresses, usernames, passwords, payloads and identifiers. Treat it as potentially sensitive and hostile at the same time.

Default controls:

- cleartext passwords are **not stored**; AEGIS keeps a SHA-256 fingerprint and length for reuse/correlation studies; when a built-in sensor must truncate an oversized credential, AEGIS explicitly distinguishes the collector-received prefix fingerprint from the sensor-reported original-value fingerprint;
- raw password storage requires the explicit `AEGIS_STORE_CREDENTIAL_SECRETS=true` opt-in and should only be used in a controlled lab with a documented purpose;
- even with that opt-in, decoded operator APIs, the console and JSON/CSV/Markdown reports never return the cleartext password; global search also removes `observed.credential.password` before matching, preventing password-existence probing through search results; operator surfaces expose only the bounded username plus password SHA-256 fingerprint/length needed for correlation;
- the collector rejects oversized bodies and bounds nested structures and strings;
- hostile values are rendered as text, never as attacker-controlled HTML;
- `AEGIS_RETENTION_DAYS` applies time-based retention continuously using canonical collector-side `collector_received_at` (with synchronized compatibility alias `received_at`), so a sensor clock cannot silently extend or shorten raw telemetry retention;
- `AEGIS_MAX_DB_EVENTS` adds a capacity ceiling so event volume cannot grow the SQLite dataset without bound;
- SQLite secure deletion is enabled and maintenance truncates the WAL after retention/capacity cleanup; backups and storage snapshots still require their own retention policy;
- SOC cases store references to source event/session IDs rather than copies of payloads or credentials, so creating a case does not silently extend telemetry retention;
- case notes and analyst metadata have a lifecycle separate from raw telemetry: define an explicit policy for them and avoid putting secrets or unnecessary personal data in notes;
- the local GeoIP/ASN adapter performs no network requests and does not send captured IPs to a third-party API;
- the optional local threat-context feed also performs no network requests; exact-match context is attached locally and the feed should be protected and retained according to its provider/licence requirements;
- operator API access fails closed when no `AEGIS_OPERATOR_API_KEY` is configured; unauthenticated access requires the explicit development-only `AEGIS_ALLOW_UNAUTHENTICATED_OPERATOR=true` opt-in;
- restrict dashboard/API access and never publish raw credentials or personal data in reports.

IP geolocation, ASN and reputation information are external context. They can identify VPNs, proxies, NAT gateways, hosting providers or compromised systems rather than the human operator. AEGIS-NEXUS does not infer human identity, threat actor attribution or campaign attribution from these fields.

Before operating an Internet-facing honeypot, define a lawful purpose, access controls, retention period, incident handling process and rules for sharing telemetry that match the jurisdiction in which the system operates.

---

## Italiano

La telemetria di un honeypot può contenere indirizzi IP, username, password, payload e identificatori. Deve essere trattata contemporaneamente come dato potenzialmente sensibile e come input ostile.

Controlli predefiniti:

- le password in chiaro **non vengono archiviate**; AEGIS conserva fingerprint SHA-256 e lunghezza per studi di riuso/correlazione; quando un sensore built-in deve troncare una credential sovradimensionata, AEGIS distingue esplicitamente il fingerprint del prefisso ricevuto dal collector dal fingerprint del valore originale dichiarato dal sensore;
- l'archiviazione raw richiede l'opt-in esplicito `AEGIS_STORE_CREDENTIAL_SECRETS=true` e va usata solo in laboratorio controllato con finalità documentata;
- anche con questo opt-in, API operatore decodificate, console e report JSON/CSV/Markdown non restituiscono mai la password in chiaro; anche la ricerca globale rimuove `observed.credential.password` prima del matching, impedendo di verificare indirettamente l'esistenza di una password tramite i risultati; le superfici operatore espongono soltanto username limitato, fingerprint SHA-256 e lunghezza necessari alla correlazione;
- il collector rifiuta body eccessivi e limita profondità, cardinalità e lunghezza delle stringhe;
- i valori ostili vengono renderizzati come testo e mai come HTML controllato dall'attaccante;
- `AEGIS_RETENTION_DAYS` applica la retention temporale in modo continuo usando il canonico `collector_received_at` del collector (con alias di compatibilità `received_at` sincronizzato), evitando che l'orologio del sensore possa estendere o accorciare implicitamente la conservazione della telemetria raw;
- `AEGIS_MAX_DB_EVENTS` impone anche un limite di capacità, evitando che il volume degli eventi faccia crescere indefinitamente il dataset SQLite;
- SQLite utilizza la cancellazione sicura e la manutenzione tronca il WAL dopo i cleanup di retention/capacità; backup e snapshot richiedono comunque una propria policy di conservazione;
- i casi SOC conservano riferimenti agli ID di eventi/sessioni invece di copie di payload o credenziali, quindi creare un caso non estende implicitamente la retention della telemetria;
- note e metadata dei casi hanno un ciclo di vita separato dalla telemetria raw: definisci una policy esplicita e non inserire nelle note segreti o dati personali non necessari;
- l'adapter locale GeoIP/ASN non effettua richieste di rete e non invia gli IP raccolti ad API di terze parti;
- il feed locale opzionale di threat context non effettua richieste di rete; il contesto viene associato localmente tramite match esatto e il feed va protetto/conservato secondo requisiti del provider e della relativa licenza;
- l'accesso API operatore fallisce in modo chiuso se `AEGIS_OPERATOR_API_KEY` non è configurata; l'accesso senza autenticazione richiede l'opt-in esplicito di solo sviluppo `AEGIS_ALLOW_UNAUTHENTICATED_OPERATOR=true`;
- limita l'accesso a dashboard/API e non pubblicare credenziali raw o dati personali nei report.

Geolocalizzazione IP, ASN e reputazione sono contesto esterno. Possono indicare VPN, proxy, NAT, provider hosting o sistemi compromessi invece della persona che ha generato il traffico. AEGIS-NEXUS non deduce identità umana, threat actor o campagne da questi campi.

Prima di esporre un honeypot a Internet definisci finalità lecita, controllo accessi, periodo di conservazione, processo di gestione incidenti e regole di condivisione della telemetria coerenti con la giurisdizione in cui il sistema opera.
