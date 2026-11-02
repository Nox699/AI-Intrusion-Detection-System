# Sprint 4 – SSH preauth og fremtidig ML-datadækning

**Status: Read-only parseraudit på GitHub. Ingen kode er installeret på Yggdrasil; eksisterende hybridmodel `ssh-if-7cc1f15288d0c73b` kører fortsat i shadow-mode uændret.**

## Observation på rigtig Pi, 2. november 2026

To særskilte, kontrollerede SSH-forsøg med ugyldige Ed25519-testnøgler gav ingen nye `events` med `outcome='failure'`, selvom OpenSSH svarede på port 22. Senere **read-only journald-analyse** fra collectorens privilegerede OpenSSH-kilder fandt:

| Logkategori | Poster i undersøgelsesperioden |
| --- | ---: |
| `Accepted` | 4 |
| `Authenticating user / preauth` | 1 |
| `Closed - invalid user` | 1 |
| `Invalid user` | 1 |
| Øvrige SSH-meddelelser | 6 |
| Journalposter med vores markerede ugyldige testbruger | **2** |

Antallet er *journalmeddelelser*, ikke antallet af angreb eller loginforsøg. De to testrelaterede linjer kan være **ét SSH-forbindelsesforsøg**, fordi OpenSSH både kan logge `Invalid user` og efterfølgende `Connection closed by invalid user`. Det må ikke tælles som to forsøg før korrelation på kilde, kildeport, boot og tid.

### Hvad virker – og hvad mangler?

- **Fungerer:** Et rigtigt succesfuldt SSH-login blev verificeret scoret af den eksperimentelle hybride Isolation Forest på Pi den 2. november kl. 17:47:48 CET: score **0,4775**, tærskel **0,6164**, `Inden for grænsen`, modelstatus `ready/shadow`, ingen ML-fund.
- **Begrænsning:** Den nuværende seks-dimensionelle SSH-ML-featurevektor skabes kun for accepterede `Accepted` eller `Failed`-autentificeringer. `Invalid user` og mange `[preauth]`-afvisninger er ikke sådanne hændelser, og derfor opstår ingen ML-score for disse forsøg.
- **Allerede dækket andetsteds:** Den eksisterende regelbaserede preauth-detektor og dashboard genkender *to* `Connection closed/reset by authenticating user ... [preauth]`-formater. Det er **ikke** en ML-detektor og dækker ikke `Connection closed by invalid user`.
- **Skelnen:** En publickey-afvisning er ikke nødvendigvis en `Failed publickey`-loglinje på denne OpenSSH-konfiguration. Et preauth-disconnect alene er ikke dokumentation for et angreb.

## Fase A – bekræft logformater uden at ændre Pi (implementeret)

`deploy/sprint4_preauth_signal_audit.py` læser journalen som `yggdrasil-worker`, bruger betroet `_COMM` og `_UID=0`, og tæller kun groft fire kendte mønstre:

- `Invalid user <username> from <address> port <port>`
- `Connection closed/reset by invalid user <username> <address> port <port> [preauth]`
- `Connection closed/reset by authenticating user <username> <address> port <port> [preauth]`
- `Disconnected from invalid user <username> <address> port <port> [preauth]`

IP'er, brugernavne, kildeporte og rå meddelelser forbliver **kun i processens hukommelse**. De viste data er alene kategorier og antal. Audit korrelerer kandidatlinjer med (`_BOOT_ID`, kilde-IP, kildeport), så samme forbindelse ikke fejlagtigt tælles som flere forskellige forbindelser. Genbrug af samme source port betyder, at dette kun er en **approksimation**, ikke en præcis sessionsoptælling. Testbrugeren er en generisk laboratoriemarkør; navnet vises ikke.

En særskilt sammenligning viser, hvor mange rækker den **eksisterende** preauth-parser allerede genkender. Scriptet læser kun historik, ikke SQLite eller credentials; ingen systemd-/UFW-/Fail2ban-ændringer, modeltræning, databaseopdatering eller Discord-beskeder.

**Kør først efter bestået CI og med en pinnet, godkendt SHA:**

~~~bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_GRON_SHA_HER'
  git fetch --no-tags origin sprint-4/preauth-ml-coverage
  test "$(git rev-parse origin/sprint-4/preauth-ml-coverage)" = "$sha"
  git show "$sha:deploy/sprint4_preauth_signal_audit.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python -       --since "2026-11-02 15:00:00"
)
~~~

## Fase B – kommende ML-udvidelse (IKKE implementeret)

For at få Isolation Forest til at registrere SSH-forsøg, der afvises før egentlig autentificering, bør vi opbygge **et separat, versionsstyret preauth-featuregrundlag**, frem for at score fire nye features med den allerede trænede seks-feature SSH-model.

Foreløbig featureidé, grupperet pr. kilde i rullende vinduer på 300 sekunder:

1. Antal **forskellige preauth-forbindelseskandidater** (korrelerede source-port-nøgler).
2. Antal `Invalid user`-meddelelser og antal forskellige ugyldige brugernavne (kun tal til ML, ikke identiteter).
3. Antal preauth-afbrydelser og forhold mellem disse og øvrige forbindelsessignaler.
4. Fordeling af preauth-hændelser i tidsintervaller.

Det er **ikke** meningsfuldt automatisk at antage, at preauth-testforsøg er normale træningsobservationer. For en eksperimentel preauth-Isolation-Forest skal vi have særskilte **syntetiske normale** træningsforløb, selvstændige mærkede hold-out-testforløb og efterfølgende kontrolleret shadow-scoring på Pi. Det er en ny model/featureversion og skal evalueres separat mod relevante regler. De tidligere 312+12 træningsrækker kan ikke bruges direkte uden ombygning og en ny dokumenteret datasplit.

Ved senere produktion skal vi holde testangreb ude af normaltræningen, bevare eksisterende SSH/UFW/Discord, samt aktivere ny scoring uden ML-beskeder, indtil falske positiver er undersøgt. Ingen ny model eller UFW-/Fail2ban-ændring følger automatisk af fase A.

## Eksamen: observation og metode

Dette er dokumentation for **en datakildebegrænsning**: journalisering, parserdækning og faktisk ML-observation er tre forskellige ting. Manglende `Failed`-rækker betyder ikke, at OpenSSH har ignoreret forsøget. Det nuværende hybrid-ML-system er allerede teknisk testet med én normal live-score; en preauth-ML-model er derimod endnu ikke udviklet eller valideret på live Pi. Det skal skelnes klart i rapporten.
