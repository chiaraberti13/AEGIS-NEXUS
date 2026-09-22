<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-F2C94C?style=flat-square" alt="Active">
  <img src="https://img.shields.io/badge/category-CYBERSECURITY-22D3EE?style=flat-square" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/stack-Python%20%2B%20Flask-8B949E?style=flat-square" alt="Python and Flask">
  <img src="https://img.shields.io/badge/languages-EN%20%7C%20IT-8B5CF6?style=flat-square" alt="English and Italian">
  <img src="https://img.shields.io/badge/licence-MIT-2EA043?style=flat-square" alt="MIT">
</p>

> Telemetria honeypot, investigazione SOC, threat research e studio della cybersecurity in una piattaforma evidence-first.

<p align="center"><a href="SECURITY.md">Sicurezza</a> · <a href="docs/THREAT_MODEL.md">Threat model</a> · <a href="docs/PRIVACY.md">Privacy e retention</a> · <a href="docs/INVESTIGATION.md">Flusso investigativo</a> · <a href="LICENSE">Licenza MIT</a></p>

---

## Cos'è AEGIS-NEXUS

AEGIS-NEXUS nasce come **Honeypot + SOC Analysis + Threat Research + Cybersecurity Learning Lab**. Il principio centrale è separare sempre osservazione grezza, enrichment esterni, dati derivati e ipotesi analitiche.

L'implementazione attuale fornisce sia la base sicura per telemetria e investigazione sia decoy SSH, web, FTP e Telnet a bassa/intermedia interazione. Comandi e payload catturati vengono solo emulati o registrati e non vengono mai eseguiti.

## Implementato ora

- Decoy isolati SSH, web, FTP e Telnet più collector Flask con ingestione JSON limitata, autenticazione fail-closed e header di identità sensore; sono supportate chiavi opzionali per singolo sensore.
- Schema eventi normalizzato con `observed`, `enrichment`, `derived`, `hypotheses` separati.
- Provenienza obbligatoria per enrichment esterni (`source` e `observed_at`).
- Enrichment locale offline GeoIP/ASN da file MMDB MaxMind forniti dall'operatore; gli IP sorgente pubblici vengono arricchiti nel collector senza inviare gli IP raccolti ad API di terze parti.
- Mapping MITRE ATT&CK e CVE accettati solo con `rationale` ed `evidence`.
- Estrazione statica deterministica da comandi/payload osservati di URL, domini, IP letterali e formati hash comuni; i valori restano artefatti derivati supportati da evidenza e non diventano automaticamente indicatori malevoli.
- Password redatte per default, con fingerprint SHA-256 e lunghezza; memorizzazione raw solo tramite opt-in esplicito.
- Correlazione persistente delle sessioni su SQLite che preferisce ID espliciti di connessione dei decoy o identità flow Suricata e usa come fallback IP sorgente, honeypot, servizio, protocollo, porta destinazione e finestra di inattività.
- API e viste SOC dedicate per eventi, profili IP, sessioni, timeline, relazioni, contesto Threat Intelligence e Study Mode.
- Gestione casi SOC evidence-preserving con classificazione dell’analista, note, tag, riferimenti a eventi/sessioni, audit trail e report JSON/CSV.
- Dashboard SOC con ricerca/filtri globali, timeline, IP unici, paesi, ASN, porte, protocolli, servizi, honeypot, credential, comandi, IDS, MITRE, heatmap temporale, Attack Map interattiva e Live Feed.
- Interfaccia IT/EN tramite dizionario i18n centrale; la telemetria viene sempre resa come testo e mai come HTML controllato dall'attaccante.
- Retention temporale continua con `AEGIS_RETENTION_DAYS` più limite di capacità `AEGIS_MAX_DB_EVENTS`; gli export investigativi JSON/CSV non includono mai password in chiaro.
- Runtime Docker hardenizzato: utente non-root, capability rimosse, root filesystem read-only, `no-new-privileges`, connessioni TCP concorrenti limitate, reti management separate per sensore e porta operatore solo su localhost.
- Container sensore con limiti CPU/memoria/PID/file descriptor e reti di esposizione/management separate, evitando un segmento management laterale condiviso tra SSH, web e legacy.
- Ingestione nativa evidence-first di eventi Suricata EVE JSON per la telemetria IDS; le signature vengono conservate come output IDS osservato senza inventare mapping MITRE o CVE.
- CI per test Python e build Docker.

## Contratto dati

Ogni evento mantiene separate le quattro classi di provenienza. Nessuna CVE, threat actor, malware family o tecnica MITRE viene inventata automaticamente: se l'evidenza non è sufficiente, il campo rimane vuoto.

```json
{
  "honeypot": "ssh-01",
  "event_type": "command",
  "severity": "medium",
  "observed": {
    "source_ip": "203.0.113.10",
    "service": "ssh",
    "protocol": "tcp",
    "destination_port": 22,
    "command": "uname -a"
  },
  "enrichment": {
    "geo": {
      "source": "provider-name",
      "observed_at": "2026-09-22T18:00:00Z",
      "data": {"country": "IT", "latitude": 41.9, "longitude": 12.5}
    }
  },
  "derived": {
    "mitre": [{
      "technique_id": "T1059",
      "rationale": "Command interpreter activity was directly observed",
      "evidence": ["observed.command"]
    }]
  },
  "hypotheses": []
}
```

## Ingestione Suricata

Invia un singolo evento Suricata EVE JSON a `POST /api/v1/integrations/suricata/eve` usando `X-Aegis-Key` e `X-Aegis-Sensor`. Gli alert diventano `ids.alert`; AEGIS conserva signature e fatti di rete come dati osservati e lascia `derived` vuoto finché non viene aggiunta separatamente un'analisi supportata da evidenza.

## Flusso investigativo

`Dashboard → evento → IP → sessione → timeline → credential/comandi/payload → Threat Intelligence/enrichment → MITRE/CVE/IOC → relazioni → caso → report → Study Mode`

Il grafo usa esclusivamente i dati realmente presenti nella sessione selezionata. La Threat Intelligence visualizza soltanto enrichment esterni memorizzati, mantenendo fonte e timestamp. Study Mode lavora sia sull'evento sia sull'intera sessione correlata, rendendo visibili i limiti dell'analisi. Consulta il [flusso investigativo](docs/INVESTIGATION.md).

## Avvio rapido

Richiede Python 3.12+ oppure Docker Compose.

```bash
cp .env.example .env
# Sostituisci AEGIS_INGEST_API_KEY con un valore casuale lungo.
docker compose up -d --build
# Dashboard: http://127.0.0.1:8600
```

Sviluppo:

```bash
python -m pip install -e '.[dev]'
pytest -q
AEGIS_DATABASE_PATH=./data/aegis.db flask --app aegis_nexus.app run --host 127.0.0.1 --port 8600
```

## Struttura

```text
src/aegis_nexus/
├── app.py          API Flask, security header e route
├── model.py        normalizzazione hostile-input e validazione provenienza
├── correlation.py regole di correlazione sessioni
├── enrichment.py  enrichment locale offline GeoIP/ASN
├── derivation.py  estrazione statica bounded degli artefatti osservati
├── casework.py     validazione bounded dei casi analista
├── backup.py       logica riusabile di backup SQLite
├── store.py        persistenza, analytics, casi, relazioni e report
├── study.py        Study Mode deterministico IT/EN
├── sensors/        decoy SSH, web, FTP/Telnet e client telemetria
├── templates/      console SOC
└── static/         i18n, grafici, mappa, live feed e investigazione
docs/
├── CASE_MANAGEMENT.md
├── DATA_PROVENANCE.md
├── ENRICHMENT.md
├── INVESTIGATION.md
├── PRIVACY.md
├── SENSOR_ISOLATION.md
└── THREAT_MODEL.md
tests/
```

## Privacy e limiti di attribuzione

La telemetria honeypot può contenere IP, credenziali e payload. Definisci finalità e periodo di conservazione, limita l'accesso degli operatori e non pubblicare dati sensibili raw. Geolocalizzazione IP, ASN e reputazione Threat Intelligence possono riferirsi a VPN, proxy, hosting, NAT o sistemi compromessi e non dimostrano l'identità della persona che ha originato l'attività.

Consulta [Privacy e retention](docs/PRIVACY.md), [Enrichment locale](docs/ENRICHMENT.md), [Threat model](docs/THREAT_MODEL.md) e [Isolamento sensori](docs/SENSOR_ISOLATION.md).

## Roadmap

I prossimi cicli implementativi sono dedicati ad ulteriori adapter controllati di threat context, export investigativi più ricchi e ulteriori integrazioni sensore/IDS. Le funzionalità vengono documentate quando sono realmente presenti nel codice.

## Licenza e uso responsabile

Distribuito con [licenza MIT](LICENSE). Utilizzalo esclusivamente su infrastrutture di tua proprietà o per le quali possiedi un'autorizzazione esplicita. Non usare AEGIS-NEXUS per contro-attaccare, accedere a sistemi di terzi o pubblicare credenziali/dati personali raccolti.

---

© Chiara Berti — 2026
