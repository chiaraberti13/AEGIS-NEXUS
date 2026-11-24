# Local enrichment / Enrichment locale

## English

AEGIS-NEXUS can enrich public source IPs with country/city coordinates and ASN context using operator-supplied MaxMind GeoIP2/GeoLite2 database files.

This adapter is deliberately **offline**:

- it performs no network requests;
- captured IPs are not sent to a third-party enrichment API;
- only globally routable source IPs are looked up;
- private, loopback, link-local, reserved and documentation ranges are skipped;
- existing `enrichment.geo` or `enrichment.asn` values are not overwritten;
- every generated record retains `source` and `observed_at` provenance;
- GeoIP/ASN remains external context and is never converted into threat-actor attribution or reputation.

`GET /api/v1/geo/attacks?hours=<n>` (operator-authenticated) aggregates approximate attack origins for geospatial visualization. Points are keyed by coarsened coordinates (~2 decimals) with event/session counts, a severity level, the GeoIP accuracy radius and `last_seen`; the response is marked `provenance: "enrichment"` and carries a standing caveat that coordinates are approximate GeoIP, not identity or attribution. The point list is hard-capped, and events whose source IP has no geolocation (private, non-global or not in the database) are counted in an explicit `unmapped` bucket rather than dropped.

The application uses the current `geoip2` Python database reader. AEGIS-NEXUS does not redistribute MaxMind databases. Obtain and maintain the database files according to the provider's licence and update policy.

### Configuration

Place the MMDB files in a local directory that is **not committed to Git**. With Docker Compose:

```bash
mkdir -p geoip
# Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in ./geoip
docker compose -f docker-compose.yml -f docker-compose.geoip.yml up -d --build
```

For a direct Python deployment:

```bash
export AEGIS_GEOIP_CITY_DB=/secure/path/GeoLite2-City.mmdb
export AEGIS_GEOIP_ASN_DB=/secure/path/GeoLite2-ASN.mmdb
```

The operator API exposes `GET /api/v1/enrichment/status` so the console can distinguish disabled enrichment from configured-but-unavailable databases.

IP geolocation is approximate infrastructure context. It must not be interpreted as a precise address, household or human location.

---

## Italiano

AEGIS-NEXUS può arricchire gli IP sorgente pubblici con paese/città, coordinate e contesto ASN utilizzando database MaxMind GeoIP2/GeoLite2 forniti dall'operatore.

L'adapter è volutamente **offline**:

- non effettua richieste di rete;
- gli IP raccolti non vengono inviati a API di enrichment di terze parti;
- vengono interrogati solo IP sorgente globalmente instradabili;
- IP privati, loopback, link-local, reserved e documentation vengono ignorati;
- eventuali valori `enrichment.geo` o `enrichment.asn` già presenti non vengono sovrascritti;
- ogni dato generato mantiene provenienza `source` e `observed_at`;
- GeoIP/ASN resta contesto esterno e non viene trasformato in attribuzione a threat actor o reputazione.

`GET /api/v1/geo/attacks?hours=<n>` (autenticato operatore) aggrega le origini approssimative degli attacchi per la visualizzazione geospaziale. I punti sono raggruppati per coordinate arrotondate (~2 decimali) con conteggi eventi/sessioni, un livello di severità, il raggio di accuratezza GeoIP e `last_seen`; la risposta è marcata `provenance: "enrichment"` e porta un caveat permanente: le coordinate sono GeoIP approssimate, non identità né attribuzione. La lista di punti ha un cap rigido e gli eventi il cui IP sorgente non ha geolocalizzazione (privato, non-globale o assente dal database) sono contati in un bucket esplicito `unmapped` invece di essere scartati.

L'applicazione utilizza il reader database Python `geoip2`. AEGIS-NEXUS non redistribuisce i database MaxMind: i file devono essere ottenuti e mantenuti dall'operatore secondo licenza e policy di aggiornamento del provider.

### Configurazione

Conserva i file MMDB in una directory locale **non versionata su Git**. Con Docker Compose:

```bash
mkdir -p geoip
# Inserisci GeoLite2-City.mmdb e GeoLite2-ASN.mmdb in ./geoip
docker compose -f docker-compose.yml -f docker-compose.geoip.yml up -d --build
```

Per un deployment Python diretto:

```bash
export AEGIS_GEOIP_CITY_DB=/secure/path/GeoLite2-City.mmdb
export AEGIS_GEOIP_ASN_DB=/secure/path/GeoLite2-ASN.mmdb
```

L'API operatore espone `GET /api/v1/enrichment/status`, così la console distingue enrichment disabilitato da database configurati ma non disponibili.

La geolocalizzazione IP è contesto infrastrutturale approssimativo e non deve essere interpretata come indirizzo preciso, abitazione o posizione fisica della persona.
