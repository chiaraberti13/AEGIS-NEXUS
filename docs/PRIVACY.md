# Privacy, retention and credential handling / Privacy, retention e credenziali

Honeypot telemetry may contain IP addresses, usernames, passwords, payloads and identifiers. Treat it as potentially sensitive and hostile at the same time.

Default controls:
- cleartext passwords are **not stored**; AEGIS keeps a SHA-256 fingerprint and length for reuse/correlation studies;
- raw password storage requires the explicit `AEGIS_STORE_CREDENTIAL_SECRETS=true` opt-in and should only be used in a controlled lab with a documented purpose;
- the collector rejects oversized bodies and bounds nested structures and strings;
- hostile values must never be inserted as HTML;
- define a retention period appropriate to your jurisdiction and research purpose and apply it consistently to backups;
- restrict dashboard/API access and never publish raw credentials or personal data in reports.

IP geolocation and ASN data are approximate and may identify VPNs, proxies, NAT gateways, hosting providers or compromised systems rather than the human operator.

---

La telemetria di un honeypot può contenere indirizzi IP, username, password, payload e identificatori. Deve essere trattata contemporaneamente come dato potenzialmente sensibile e come input ostile.

Controlli predefiniti:
- le password in chiaro **non vengono archiviate**; AEGIS conserva fingerprint SHA-256 e lunghezza per studi di riuso/correlazione;
- l'archiviazione raw richiede l'opt-in esplicito `AEGIS_STORE_CREDENTIAL_SECRETS=true` e va usata solo in laboratorio controllato con finalità documentata;
- il collector rifiuta body eccessivi e limita profondità, cardinalità e lunghezza delle stringhe;
- i valori ostili non devono mai essere inseriti come HTML;
- definisci un periodo di retention adeguato a giurisdizione e finalità di ricerca e applicalo anche ai backup;
- limita l'accesso a dashboard/API e non pubblicare credenziali o dati personali nei report.

Geolocalizzazione IP e ASN sono approssimativi e possono indicare VPN, proxy, NAT, provider hosting o sistemi compromessi invece della persona che ha generato il traffico.
