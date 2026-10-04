---
name: roadmap-next
description: Avanza la roadmap di AEGIS-NEXUS. Usala ogni volta che il compito è completare il prossimo punto non spuntato di ROADMAP.md, verificarlo, spuntarlo e fare commit e push su main.
---

# Prossimo punto della roadmap — AEGIS-NEXUS

Procedura per una sessione automatica che deve chiudere **un** punto di `ROADMAP.md`
e pubblicarlo su `main` senza intervento umano. Segui i passi in ordine.

## 1. Allinea il repository

```bash
git checkout main
git pull --rebase origin main
python -m pip install -e '.[dev]'
```

Lavora sempre partendo dall'ultimo `main`: altre esecuzioni pianificate possono aver
spuntato punti poco prima di te.

## 2. Scegli il punto giusto

Trova i candidati con:

```bash
grep -n -E '^\s*[-*] \[ \]' ROADMAP.md | head -20
```

Il punto da fare è il **primo vero task** non spuntato, in ordine di documento, con
queste eccezioni:

- La legenda è una riga unica in grassetto e non compare nel grep.
- I punti marcati _(evaluate)_ sono spike di ricerca: il risultato può essere un ADR
  in `docs/` che accetta o respinge la funzionalità; in quel caso l'ADR è il
  deliverable e il punto si può spuntare.
- **Salta** i punti che non si possono chiudere da una sessione cloud: richiedono
  account o servizi esterni da attivare (Vercel, impostazioni GitHub, branch
  protection), credenziali reali, hardware, laboratorio live o decisioni della
  proprietaria. Passa al successivo e segnalalo nel resoconto finale.
- Se un punto è troppo grande per una sola sessione, completa una parte coerente e
  verificata e marcalo come **parziale** con la convenzione del repository (vedi
  sotto), mai come completato.

Prima di scrivere codice rileggi il punto, la sua sezione e il criterio di
completamento: il lavoro è finito solo quando quel criterio è soddisfatto.

## 3. Implementa

Il punto si può spuntare solo se rispetta **tutta** la Definition of Done in testa
a `ROADMAP.md`:

1. test per il caso normale **e** per input ostili, sovradimensionati o malformati
   su tutto ciò che tocca dati catturati;
2. provenienza delle evidenze esplicita (Observed / Enrichment / Derived /
   Hypotheses), perdita di evidenze registrata e mai silenziosa;
3. nuovi campi valutati per impatto privacy (IP sorgente, username e credenziali
   sono dati personali) e coperti dalla retention;
4. nuova superficie d'attacco o flusso di dati riportato in
   `docs/THREAT_MODEL.md`;
5. testi per l'utente in **italiano e inglese** (`src/aegis_nexus/static/i18n.js`);
6. documentazione in `docs/` aggiornata nello stesso commit.

Mai committare segreti, credenziali reali o dati personali.

## 4. Verifica

Esegui i controlli che la CI esegue su questo repository e correggi ogni errore prima
di proseguire:

```bash
python -m compileall -q src
python -m py_compile scripts/*.py
bash -n scripts/egress_guard.sh
bash scripts/egress_guard.sh validate
node --check src/aegis_nexus/static/app.js
node --check src/aegis_nexus/static/i18n.js
pytest -q
```

Se `docker` è disponibile esegui anche i controlli `docker compose ... config -q`
presenti in `.github/workflows/ci.yml` (con le variabili `AEGIS_*_API_KEY` di
prova indicate lì); se non lo è, dillo nel resoconto. Se aggiungi un target al
`Makefile`, aggiungilo anche alla riga `make -n ...` della CI.

Se un controllo fallisce per cause preesistenti estranee al punto (verificabile
eseguendolo anche su `main` senza le tue modifiche), non nasconderlo: annotalo nel
resoconto.

## 5. Aggiorna ROADMAP.md

Sostituisci `- [ ]` con `- [x]` sulla riga del punto, senza altre modifiche al
testo. Se il punto è stato solo in parte completato, lascialo `[ ]` e aggiungi in
coda una nota breve su cosa è stato fatto e cosa manca.

## 6. Commit e push

```bash
git add -A
git status            # controlla che non ci siano file temporanei, .env o segreti
git commit            # messaggio secondo la convenzione sotto
git pull --rebase origin main
git push origin main
```

Convenzione dei messaggi: Conventional Commits in inglese, minuscolo, all'imperativo, es.
`feat: detect sensor telemetry gaps with per-stream sequence numbers` o
`docs: document telemetry gap detection and mark roadmap item done`.

Se il push viene rifiutato perché `main` è avanzato, ripeti `git pull --rebase`,
risolvi gli eventuali conflitti (in `ROADMAP.md` tieni le spunte di entrambi), riesegui
i test interessati e ripeti il push. **Mai** `--force`, mai riscrivere la storia di
`main`, mai `--no-verify`.

## 7. Resoconto

Chiudi con un riepilogo breve: punto scelto (con ID), file modificati, controlli
eseguiti con esito, hash del commit ed esito del push, punti saltati e perché.
