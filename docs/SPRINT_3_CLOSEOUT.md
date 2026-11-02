# Sprint 3 – Afslutningskontrol

**Status:** Kernefunktioner er demonstreret på Pi. Netværksgraferne er **nu installeret på Pi** efter bestået CI,
frisk offline-backup og server-side smoke-tests. Browser-visning,
screenshot og observation af normaldrift afventer.

## Verificeret i drift

- Schema v4 migreret med bevaret SSH-historik og Discord-outbox.
- Collector, web og notifier var aktive efter migration og UFW-opt-in.
- Netværksindsamling aktiv, UFW logniveau low; eksperimentel
  alarmgrænse 5 forskellige blokerede TCP SYN-porte på 60 sekunder.
- Første scanning ved grænse 6: 8 loggede SYN på 5 porte, ingen alarm.
- Anden scanning ved grænse 5: 1 scan-alarm, 10 evidensfund
  grupperet i ét alarmforløb, 1 ny leveret Discord-besked.
- 300-sekunders cooldown samler nye fund med samme detektor og
  kilde/sensorgruppe, men er ikke en garanti mod alle gentagelser.

## Det der mangler for funktionel afslutning

1. Klargør ny graf-release med deploy/sprint3_charts_prepare.sh
   fra en bestemt, grønt CI-testet Git-SHA. Den bygger wheel og
   tager privat backup af kørende venv uden tjenestestop.
2. Gennemgå stage-output, derefter kør deploy/sprint3_charts_deploy.sh
   fra præcis samme commit. Scriptet stopper kun IDS-tjenesterne,
   tager offline SQLite/schema-v4 backup og beskyttet kopiering
   af data, notifier-state og config, installerer wheel med
   korrekte kodefilrettigheder og genstarter alt med kontroller.
   Scriptet må aldrig genkøres automatisk efter fejl.
3. Åbn dashboard gennem eksisterende SSH-tunnel til homelab.
   Kontrollér Netværk: graf over blokerede TCP SYN pr. interval,
   samt højst 10 navngivne porte og én kategori Øvrige porte.
   Graf-API må kun returnere aggregater, ikke private IP'er.
4. Gem et privat screenshot af graferne som S3-J til rapporten.
   Gem også S3-F (alarmdetaljer) og S3-G (Discord-notifikation).
   Redigér private detaljer før upload/deling.
5. Verificér alle tre IDS-services, schema v4 og SQLite quick_check,
   journaladgang, web-login, autentificeret netværksgraf,
   Discord-outbox og UFW low efter opdatering.
6. Registrér et kort afgrænset normaldriftsvindue uden bevidst
   scanning, og se efter falske scanalarmer. Et lille antal
   observationer kan ikke bevise en lav falsk-positiv-rate.
   Hvis muligt fortsættes stabilitetsmåling hen over et døgn.

## Stopkriterium

Efter godkendt live-opdatering, bekræftede grafer, intakt
SSH/Discord, screenshots og dokumenterede begrænsninger markeres
Sprint 3 funktionelt afsluttet. Det er ikke det samme som statistisk
dokumenteret detektionskvalitet eller komplet 24-timers stabilitet.

Sænk ikke tærsklen yderligere, og lav ikke fuld TCP-portscanning
alene for at opnå en grøn status. UFW low kan ratebegrænse loggen;
de registrerede pakker er ikke alle afsendte netværksforsøg.

Derefter prioriteres Isolation Forest og sammenligning med
regelbaseret SSH-detektion til eksamensrapporten.

## Praktisk installationsresultat – 2. november 2026

**Staging og deployment gennemført med PASS på Pi.** Installeret
Git-SHA: `0cdcf4c3b6c62718f1ef4d5c5d35ee96362bd581`.
Wheel, fuld tidligere venv-backup og offline schema-v4-backup blev
verificeret. CLI-import virkede som worker, web og notifier.
Det nye graf-API er beskyttet af login (HTTP 401 uden session),
login-side svarer 200. SQLite-historik og Discord-levering bevaret
(`pending=0`, `delivered=2`). Alle tre services er aktive og UFW
forbliver på `low`.

**Backup:** `/var/backups/yggdrasil-ids/sprint3-charts-offline-PS5JlXUx`.
**Rollback-venv:** `/var/backups/yggdrasil-ids/sprint3-charts-prepared-0cdcf4c3b6c62718f1ef4d5c5d35ee96362bd581/previous-venv.tar.gz`.

**Nu mangler kun browseraccept af de to grafer og S3-J screenshot,
plus en afgrænset observation uden testscanning.** Udrulningsscripts
skal ikke køres igen. Dette er ikke endnu dokumentation for 24 timers
stabilitet eller en estimeret falsk-positiv-rate.

## Første efterfølgende netværksobservation

Read-only optælling fra **02.11.2026 kl. 01:15 CET** gav **139
firewallposter og 0 nye portscan-alarmforløb** (baseret på
`first_seen`). Dette er en afgrænset kontrol af alarmmængde,
ikke et estimat af falsk-positiv-rate: trafikken er ikke
manuelt klassificeret i alle tilfælde. Spørgsmålet om eventuel
testtrafik i tidsintervallet er ikke afklaret.

**Stadig åbent:** visuel kontrol af begge `/network`-grafer
i brugerens browser og screenshot S3-J. Ingen grund til at
genkøre wheel-installation eller gentage portscanningen.
