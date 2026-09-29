# Synthetic attack-replay corpus / Corpus sintetico di attack replay

## English

Each `vN/` directory is a released, immutable regression dataset. Its `corpus.json` declares:

- a corpus schema and content version;
- the required protocol inventory and exact fixture count for each protocol;
- normalized AEGIS events or raw Suricata EVE records;
- exact detection-rule hit counts expected from deterministic replay.

The corpus is synthetic test data only. IP addresses come from the RFC 5737 documentation networks, domains use the reserved `.invalid` suffix, credentials are fabricated, and no payload is executed.

Do not edit a released version in place after downstream tests depend on it. Copy the latest directory to a new major `vN`, update its versions and expectations, and add regression coverage for the new version. Consumers should reject an unsupported `schema_version` instead of guessing its meaning.

## Italiano

Ogni directory `vN/` è un dataset di regressione rilasciato e immutabile. Il relativo `corpus.json` dichiara:

- versione dello schema e del contenuto del corpus;
- inventario dei protocolli richiesti e conteggio esatto delle fixture per protocollo;
- eventi AEGIS normalizzati oppure record Suricata EVE grezzi;
- conteggi esatti delle detection attese dal replay deterministico.

Il corpus contiene esclusivamente dati sintetici di test. Gli indirizzi IP appartengono alle reti di documentazione RFC 5737, i domini usano il suffisso riservato `.invalid`, le credenziali sono inventate e nessun payload viene eseguito.

Non modificare una versione rilasciata quando test downstream dipendono già da essa. Copia la directory più recente in una nuova major `vN`, aggiorna versioni e aspettative e aggiungi la relativa copertura di regressione. I consumer devono rifiutare una `schema_version` non supportata invece di interpretarla implicitamente.
