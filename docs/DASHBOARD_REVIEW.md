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
