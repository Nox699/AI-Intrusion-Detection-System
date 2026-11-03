# Dashboard-review – Yggdrasil IDS (før eksamen)

**Dato:** 3. november 2026. **Status:** Kodegennemgang, ikke visuel
browseraccept. Eksisterende installeret dashboard ændres ikke af
denne udviklingsbranch, indtil brugeren eksplicit kører en sikker
web-release med backup og rollback.

## Gennemgået ud fra Flask-kode og Jinja-templatefiler

Det eksisterende Flask-dashboard har login og følgende sider:
**Overblik, SSH-hændelser, Før login, Netværk, Alarmer,
Machine learning, Systemstatus**. Der findes
separate templates og CSS i mørkt tema, oversigtsgraf
for SSH-aktivitet, netværksgrafer for UFW, filtrerbare
tabeller og statusvisning. Webserveren er
autentificeret og bruger den eksisterende produktions-
SQLite som **read-only** datakilde.

**Konkret UX-rettelse kun på udviklingsbranchen:**
Topbarens breadcrumb var fejlagtigt hardcoded til
`Dit sikkerhedsoverblik / SSH` på *alle* sider.
Nu følger navnet den aktuelle route; serverlabel
er gjort generisk til `IDS · Privat server`.
En Python-webtest kontrollerer alle eksisterende
sider. Ændringen er **ikke endnu installeret** på Pi.

**Sudo er ikke en selvstændig dashboard-side endnu.**
Den vedvarende `yggdrasil-sudo-shadow.timer` skriver
til `/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3`
med ejer `yggdrasil-worker` og privat mappe `0700`.
`yggdrasil-web` kan **ikke** læse den database, hvilket
er tilsigtet. Vores sudo-ML-benchmark ligger i en
privat mappe under brugerens hjem, og er hverken
en driftsmodel eller en datakilde i webdashboardet.
Derfor må den eksisterende `/model`-side **ikke**
præsentere syntetiske sudo-ML-tal som live SSH-scoring.

## Minimal UI, hvis sudo-siden skal med til eksamen

- Sudo-side med tydelig **Shadow – ingen automatiske alarmer**.
- Kun aggregerede målinger: lagrede sudo-processer, sidste
  journal-checkpoint, normal aktivitet og kandidatantal,
  med angivelse af observationsperioden.
- En separat **ML-eksperiment**-sektion med
  `synthetic_only=true`, modelversion og
  TP/FP/TN/FN for regler kontra Isolation Forest.
- Følg sikkerhedsgrænser: **aldrig** åbn direkte
  adgang til `0700`-databasen for webbrugeren.
  Kræv en eksplicit, snæver og atomisk
  publicering af **sanitiserede aggregater**,
  verificeret skema, aldersangivelse og korrekt
  read-only adgang – uden sudo-forsøgsdetaljer,
  rå journals, credentials eller uverificerede
  placeholders. Ingen ny live sudo→Discord-funktion
  forudsættes for en sådan read-only UI.

## Visuel accept der mangler

Åbn den installerede, private app gennem SSH-tunnelen
til Raspberry Pi'ens `127.0.0.1:8765`, og gennemgå
**Overblik**, **Netværk**, **Machine learning** og
**Systemstatus** på desktop og eventuelt mobilbredde.
Send anonymiserede screenshots til gennemgang;
det konkrete layout kan ikke vurderes alene ud fra
templates/CSS, fordi vi ikke har set appen gengivet
i brugerens browser.

**Evidens S5-15** bruges til visuel gennemgang af
det eksisterende dashboard og **må ikke** beskrives
som screenshot af sudo, før der faktisk er
implementeret en sikker sudo-side og en ny web-release.

## Visuel gennemgang af de fire modtagne skærmbilleder (3. november 2026)

Brugeren viste de **faktisk installerede** sider Overblik, Netværk,
Alarmer og Machine learning. Browseren var zoomet langt ud.
Derfor er meget lille tekst og store tomme arealer på
skærmbillederne **ikke i sig selv tegn på et CSS-problem**.
Sammenhængende mørkt tema, grønne accenter, sidebar, kort,
datatabeller og ML-scorelister fremstår konsistente.
Skærmbillederne er set i samtalen, men **ikke uploadet
til den offentlige GitHub-repo**.

Konkrete observationer:

- Topbaren viser `/ SSH` også på Netværk, Alarmer og
  Machine learning. Dette bekræfter **gammel installeret webversion**:
  breadcrumb-fixet er kun på udviklingsbranchen.
- Netværk viser mange registrerede **UFW-blokerede UDP-pakker**
  i tabellen, men graferne er specifikt for **blokerede
  TCP SYN-pakker**. Derfor kan graferne legitimt være tomme,
  uden at tabellens trafik mangler. Tom Plotly-datoakse
  viste misvisende **år 2000**. Dette er rettet
  **kun på udviklingsbranchen**: akserne skjules,
  når den filtrerede dataserie er tom. Et funktionelt
  regressionstest-tjek kontrollerer den tilsigtede
  tomvisningsopsætning i JS-koden.
- Overblik viser SSH-statistik og indlæst model;
  Machine learning viser SSH-modellen som
  eksperimentel skyggemodel og observationer.
  Ingen sudo-resultater i web endnu.
- Alarmer viser 0 for valgte periode.
  Et tomt alarmpanel viser ikke nødvendigvis, at
  tidligere laboratoriealarmer aldrig har eksisteret;
  den valgte periode og det faktiske datagrundlag
  skal undersøges særskilt.

**Konklusion:** Dashboardet er allerede brugbart som
SSH/UFW/ML-overblik. Næste udvikling bør være en
sikker, tydeligt **shadow-markeret sudo-visning**,
men ingen databasepermissions må svækkes.
Før en ny webrelease kræves eksplicit deploy/rollback
med backup af installeret kode og relevante data.
Brugeren bør gennemgå de samme sider ved browserzoom
omkring **100 %** for at bedømme faktiske
tekststørrelser og pladsforbrug.
