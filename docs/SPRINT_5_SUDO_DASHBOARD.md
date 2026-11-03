# Sprint 5 – sikker sudo-webvisning (gated deployment)

**3. november 2026 · Yggdrasil / Debian 13 / Raspberry Pi 5**

Mål: vise ægte sudo-shadow-tællinger og en redeligt mærket,
historisk syntetisk Isolation Forest-vs-regler-benchmark i
samme mørke interface som SSH/UFW. Den produktionsnære
sudo-sensor, collector, notifier, UFW og SSH må ikke ændres.

## Adskilte tillidsgrænser

```text
                    KUN yggdrasil-worker (0700)
  journald → sudo-shadow.timer → privat sudo-shadow.sqlite3
                                       │ read-only
                                       ▼
                             sudo-ui-export.timer
                                       │ anonym tællefil (0640)
                                       ▼
                  /var/lib/yggdrasil-sudo-public/sudo-status.json
                  mappe: 0750 worker:yggdrasil-data
                                       │ read-only
                                       ▼
                        yggdrasil-web /sudo (login)
                                       │
                   synthetic sudo_benchmark.json (pakket kilde)
```

- Webkontoen **har ikke** adgang til privat sudo-SQLite, UID,
  PID, rå journalposter eller Discord-webhook. Den læser kun
  en valideret JSON-fil med tællinger og timestamp.
- Det er **ikke** en `sudo`-alarmstrøm. Ingen forbindelser
  til produktionens `alerts`, `discord_outbox` eller
  live sudo-ML. Den gamle webapp er fortsat privat på loopback.
- Webformularen er loginbeskyttet. Manglende, beskadiget eller
  forældet eksport viser **ukendt/forældet**; aldrig fabrikeret
  0 eller grønt.
- Resultaterne `sudo-if-4f95328112e7423b`, testregelsæt
  TP=24, FP=0, FN=8 og IF TP=12, FP=4, FN=20
  er **faktisk observerede** 3. november, men er udelukkende
  syntetiske laboratorietal. De ligger som versioneret, lokal
  pakkedata, ikke som en live model.
- Tomme TCP SYN-grafer har nu usynlige akser, så Plotly
  ikke viser misvisende år 2000, når de eneste loggede
  UFW-hændelser eksempelvis er UDP.

## Gated installation (én fase ad gangen)

**Forberedelse:** kræv grøn CI på pinned `sha` og
fire eksisterende aktive IDS-services/timer. Hvis nogen
eksisterende installation eller publiceringsmappe allerede
findes, stopper install-scriptet.

1. **Stage eksportøren uden at starte timeren:**
   `bash <(git show "$sha:deploy/sprint5_sudo_ui_stage_pi.sh") "$sha"`.
   Dette installerer kun root-ejet script og separate systemd-units.
2. **Aktivér eksportøren særskilt:**
   `bash <(git show "$sha:deploy/sprint5_sudo_ui_activate_pi.sh") "$sha"`.
   Et første oneshot skal lykkes, `yggdrasil-web` skal
   kunne læse **kun** den anonymiserede fil, og test af
   webadgang til private sudo-SQLite skal give **ingen adgang**.
   Først derefter `enable --now` for eksporttimer.
3. **Stage ny webkode uden ændring i pip/systemd:**
   `bash <(git show "$sha:deploy/sprint5_sudo_ui_web_stage_pi.sh") "$sha"`.
   Koden ligger root-ejet på
   `/opt/yggdrasil-sudo-ui-web/src`. Kører læsebaseret
   Flask-adgangstest under `yggdrasil-web`, inklusive
   autorisationskravet på `/sudo`.
4. **Forhåndsvisning på særskilt loopback-port:**
   `bash <(git show "$sha:deploy/sprint5_sudo_ui_preview_pi.sh") "$sha"`.
   Denne kommando kører **i forgrunden** som webbrugeren.
   Med en ny SSH-tunnel `ssh -N -L 8766:127.0.0.1:8766 vidar@yggdrasil`
   kan webbruger se `http://127.0.0.1:8766/sudo`.
   Afslut med Ctrl-C; produktion på 8765 er uændret.
5. **Kun efter visuel accept:** Aktivér
   `deploy/sprint5_sudo_ui_web_activate_pi.sh`. Den
   gemmer kopi af eksisterende web-unit og opretter én
   root-ejet systemd drop-in, som giver **kun webtjenesten**
   `PYTHONPATH=/opt/yggdrasil-sudo-ui-web/src`.
   Den genstarter **kun yggdrasil-web.service**,
   verificerer login, collector/notifier/shadow/export-timere
   og kan automatisk fjerne drop-in igen ved fejl.
   Ingen `pip install` og ingen SQLite-migration.

**Rollback for web:** `deploy/sprint5_sudo_ui_web_rollback_pi.sh "$sha"`
fjerner kun det verificerede drop-in og genstarter
den originale webtjeneste. Den rører ikke kodepakker,
journal, registrerede alarmer eller notifier-state.

**Rollback for eksport:** `deploy/sprint5_sudo_ui_export_rollback_pi.sh`
stopper kun eksporttimer og fjerner eksporter-kode samt
den anonymiserede statusfil, ikke sudo-shadow-databasen.
En webside, som stadig findes under rollback,
viser da korrekt status **ikke tilgængelig**.

## Acceptance og screenshots

- [x] CI grøn for Python 3.11 og 3.13 ved commit `02de116b4a2a90435b4135e220be8371687c2576`.
- [x] Eksportservice og timer aktiv, webkonto kan læse
      anonym fil og ikke privat sudo-SQLite.
- [ ] Preview-port 8766 viser Sudo-siden bag login.
- [ ] Siden viser ægte checkpoint og tællinger,
      ikke en manisk/grøn successtatus ved databrud.
- [ ] ML-tabellen er markeret **Syntetisk · Ikke live**.
- [ ] Eksisterende SSH, Netværk, Alarmer og Machine learning
      på port 8765 er uændrede før release.
- [ ] Efter release er kun webtjenesten genstartet;
      alle fire tidligere enheder og exporter er stadig aktive.
- [ ] Screenshot af sudo-status og ML-test (S5-16) uden
      adgangsoplysninger/IP-adresser hvis publiceret i bilag.

## Begrænsninger

Denne UI er en anonymiseret **opsummering**, ikke en
individuel hændelsesliste eller udvidet forensisk analyse.
Der sker ingen modeltræning eller klassifikation via
HTTP. Produktions-sudo er stadig **regler i shadow-mode**;
Isolation Forest sammenlignes i laboratoriet.
Der er endnu ingen dokumenteret langtids-FPR
eller automatisk sudo→Discord-detektion.


## Første aktivering af anonym eksport (ejerens terminaloutput 3. november 2026)

Efter stagen af den pinned eksportør rapporterede ejeren:
`PASS: sudo UI exporter staged; service and timer NOT started/enabled`.
Efter særskilt aktivering rapporterede scriptet:
`PASS: Web user can read only safe anonymous sudo summary`,
checkpoint `1793704743.288613`, **126** sudo-logposter i
seneste 24 timer, **0** regelkandidater og
`PASS: Anonymous sudo dashboard export ACTIVE`.
`systemctl list-timers` viste næste planlagte eksport
**2026-11-03 12:19:50 CET**. En første aktiv timer
viser planlægning, ikke endnu langtidspålidelighed.
Ingen genstart af produktions-web/SSH/UFW/Discord blev udført.

**Næste gated trin:** Stage den nye webkode til separat
loopback-forhåndsvisning 8766. Den installerede
webtjeneste på 8765 er stadig uændret.

## Feedbackrunde 2: Hændelser før ML og advarselstrekanter i navigationen

Brugerens UI-preview på 8766 viste, at syntetisk
Isolation Forest-vs-regler-benchmark fyldte meget i forhold
til den operative sudo-overvågning. Prioriteten blev derfor
ændret **før release**:

1. Kortene viser fortsat den anonyme, løbende sudo-status.
2. **Seneste mistænkelige sudo-aktivitet** vises først,
   med op til **otte særskilte regelkandidater** fra
   de seneste 24 timer – også når de ikke er blandt
   de sidste 15 normale processer.
3. **Seneste 15 sudo-forløb**: én række pr.
   `(boot_id, uid, pid)`-gruppe, **kun**
   tidspunkt, begrænset kategorikode og en af
   `rule_candidate`, `review`, `normal`.
   Flere PAM-/sessionloglinjer fra samme proces
   tæller ikke som separate brugerhandlinger.
   Sammenkoblingen kan være tvetydig ved PID-genbrug;
   det er ikke egentlig forensisk rekonstruktion.
4. Sensorstatus og to forklarlige sudo-regler.
5. **Syntetisk Isolation Forest vs. regler nederst**,
   konsekvent mærket `Eksperiment · Ikke live`.

**Privatliv:** Udvidelsen offentliggør en **ny** fil
`/var/lib/yggdrasil-sudo-public/sudo-activity.json`
med *kun* disse begrænsede, anonymiserede felter.
Den gamle `sudo-status.json` beholder sin præcise
`sudo-shadow-summary-v1`-kontrakt, så den
tidligere installerede forhåndsvisning fortsat
fungerer under eksportøropgraderingen. Den nye
fil har separat `sudo-shadow-activity-v1`-kontrakt,
egne loftsgrænser, validering, maximumalder og
fail-closed fejlvisning. Ingen UID, PID, raw commands,
journaltekst, journalcursor eller secrets bliver
vist til browseren.

**Advarsel i venstre menu:** Et lille orange
`⚠` vises ved **Netværk**, når den eksisterende
produktionsdatabase har en `network.tcp_port_scan`-
**alarmforekomst** med `last_seen` inden for 24 timer.
SSH-hændelser og Før login har tilsvarende indikatorer
for deres eksisterende alarmtyper; **Alarmer** viser
markering ved ethvert relevant alarmforløb. Alle
tællinger hentes via en **autentificeret**,
skrivebeskyttet `/api/nav-alerts` ca. hvert
15. sekund. De er **ikke ulæste notifikationer**
eller nye Discord-beskeder og kræver ikke
kvitteringsdatabase. Sudo-shadow-regelkandidater
regnes **ikke** for aktive produktionsalarmer.
Et mislykket API-kald må aldrig forvandles
til konklusionen »0 alarmer«.

### Sikker opgradering fra den allerede installerede preview

Eksisterende tilstand: første `sudo-ui-export.timer`
er aktiv, og en 8766-preview med kodestage
`56c4d4a54c6a1c4a2467a526691a50b7706b1df4`
er åbnet manuelt. Produktionsweb på 8765 er
ikke opdateret.

- **Gate A – anonym eksportør:**
  `deploy/sprint5_sudo_activity_upgrade_pi.sh "$sha"`
  kontrollerer forrige pinned installeret exporter
  (`02de116b4a2a90435b4135e220be8371687c2576`),
  gemmer en root-beskyttet backup, stopper
  **kun eksporttimeren kortvarigt**, installerer
  den nye publisher, kræver et bestået oneshot,
  dokumenterer at `yggdrasil-web` kun ser de
  anonyme filer, og genstarter eksporttimeren.
  Ved fejl gendannes original exporter og timer.
  Manuel rollback:
  `deploy/sprint5_sudo_activity_rollback_pi.sh "$sha"`.
  **Sudo-shadow-sensoren, collector, notifier og
  almindelig webserver genstartes ikke.**
- **Gate B – stoppet forhåndsvisning:**
  Stop brugerens tidligere 8766-preview med
  Ctrl+C. `deploy/sprint5_sudo_ui_preview_upgrade_pi.sh "$sha"`
  kontrollerer at porten er fri og koden matcher
  oprindeligt staged `56c4d4...`, tager en
  root-beskyttet kildebackup, erstatter **kun
  den stagerede preview-kode**, verificerer
  `/sudo` og `/api/nav-alerts` kræver login
  og at begge anonyme JSON-opsummeringer kan læses.
  Ingen aktiv webserver ændres.
- **Gate C – visuel accept:**
  Åbn den nye 8766-preview via det eksisterende
  SSH-tunnelprincip. Se især at seneste aktivitet
  står **før** benchmark, og at begge fejlklasser
  har korrekte badges. Simuler IKKE et
  sikkerhedsangreb i produktion for at få et
  orange trekantikon; unit/web-tests bruger
  isolerede fiktive alarmer.
- **Gate D – web-only release:**
  Først efter screenshot- og GUI-accept må den
  allerede udviklede `sprint5_sudo_ui_web_activate_pi.sh`
  køre. Den genstarter kun webtjenesten og
  kan vendes tilbage med
  `sprint5_sudo_ui_web_rollback_pi.sh`.

**Evidens:** Nyt screenshotforslag **S5-17** for
kandidat- og procesliste før eksperimenttabellen,
og **S5-18** for en reproducerbar, syntetisk
CI/webtest af orange menuadvarsel. Der må ikke
påstås en aktuel portscanning eller en ægte
sudo-alarm, hvis den eneste forekomst er lavet
som testfixture.
