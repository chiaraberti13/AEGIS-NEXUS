# Artifact quarantine / Quarantena artefatti

AEGIS treats attacker-supplied files as hostile evidence. Quarantine is a storage boundary, not a malware-analysis sandbox.

## English

### Capture paths

- Web: `POST /upload` accepts one bounded multipart file and forwards its bytes to the collector over the sensor management network.
- FTP: the legacy decoy supports bounded `STOR` through `EPSV` on the dedicated passive data port. Active `PORT` mode is deliberately disabled so the decoy never opens a new outbound connection to an attacker-controlled address.
- SSH: the current decoy emulates an interactive shell only. SCP/SFTP are not implemented, so AEGIS does not claim to capture SSH file uploads.

### Storage boundary

Exposed sensor containers do not persist uploaded files. `SensorClient.quarantine_artifact()` sends raw bytes to the collector through authenticated/signed `POST /api/v1/quarantine`. The collector writes the artifact beneath `AEGIS_QUARANTINE_DIR` using a random artifact ID and a `.bin` suffix.

The quarantine store:

- computes SHA-256 before returning artifact metadata;
- limits each artifact with `AEGIS_QUARANTINE_MAX_BYTES`;
- limits retained file count with `AEGIS_QUARANTINE_MAX_FILES`;
- serializes count enforcement across collector workers on POSIX deployments;
- creates the quarantine directory with restrictive permissions where supported;
- writes files with mode `0600` where supported;
- sanitizes the supplied filename to basename metadata only;
- never executes, imports, parses or renders the stored bytes;
- exposes no GET/download route for artifact content.

The event stream stores artifact metadata and evidence references only: artifact ID, SHA-256, size, bounded original filename/content type and quarantine state. Attacker bytes are not copied into event JSON.

### Operational limits

Defaults are 256 KiB per artifact and 1000 retained files. Operators should choose lower limits when the deployment does not require larger samples. Reaching a size/count limit rejects the upload rather than silently truncating it, preserving evidence semantics.

Quarantine is not a substitute for a malware-analysis sandbox. Any future artifact download/export must be authenticated, audited, attachment-only and must not be rendered inline by the browser.

## Italiano

AEGIS tratta ogni file fornito dall'attaccante come evidenza ostile. La quarantena è un confine di storage, non una sandbox di malware analysis.

### Percorsi di acquisizione

- Web: `POST /upload` accetta un singolo file multipart bounded e inoltra i byte al collector tramite la rete management del sensore.
- FTP: il decoy legacy supporta `STOR` bounded tramite `EPSV` sulla porta dati passiva dedicata. La modalità active `PORT` è intenzionalmente disabilitata, così il decoy non apre nuove connessioni outbound verso indirizzi controllati dall'attaccante.
- SSH: il decoy attuale emula soltanto una shell interattiva. SCP/SFTP non sono implementati, quindi AEGIS non dichiara di catturare upload SSH.

### Confine di storage

I container sensore esposti non persistono i file caricati. `SensorClient.quarantine_artifact()` invia i byte grezzi al collector tramite `POST /api/v1/quarantine` autenticata e firmata. Il collector salva l'artefatto sotto `AEGIS_QUARANTINE_DIR` usando un artifact ID casuale e suffisso `.bin`.

Il quarantine store:

- calcola SHA-256 prima di restituire i metadata;
- limita ogni artefatto con `AEGIS_QUARANTINE_MAX_BYTES`;
- limita il numero di file conservati con `AEGIS_QUARANTINE_MAX_FILES`;
- serializza il controllo del limite tra worker del collector nei deployment POSIX;
- crea la directory di quarantena con permessi restrittivi dove supportato;
- scrive i file con modalità `0600` dove supportato;
- riduce il filename fornito al solo basename usato come metadata;
- non esegue, importa, analizza o renderizza mai i byte conservati;
- non espone route GET/download per il contenuto degli artefatti.

Nel flusso eventi vengono conservati solo metadata e riferimenti di evidenza: artifact ID, SHA-256, dimensione, filename/content type bounded e stato di quarantena. I byte dell'attaccante non vengono copiati nel JSON dell'evento.

### Limiti operativi

I default sono 256 KiB per artefatto e 1000 file conservati. Quando non servono campioni più grandi è preferibile impostare limiti inferiori. Il superamento dei limiti rifiuta l'upload invece di troncarlo silenziosamente, preservando la semantica dell'evidenza.

La quarantena non sostituisce una sandbox di malware analysis. Qualsiasi futura funzione di download/export dovrà essere autenticata, auditata, attachment-only e non dovrà renderizzare il file inline nel browser.
