# Sudo i drift på Yggdrasil

Funktionsopdelingen er **sudo-regler som alarmudløser** og den frosne, blandede
Isolation Forest-model som **løbende shadow-vurdering**. Modellen analyserer
liveaktivitet, men opretter ingen alarmer eller Discord-job. Nye observationer
bruges ikke til træning eller ændring af tærsklen.

## Verificeret installation

| Del | Placering eller version |
| --- | --- |
| Produktionsdashboard | SSH-tunnel til `127.0.0.1:8765/sudo` |
| Produktionsdatabase | `/var/lib/yggdrasil-ids/events.sqlite3`, schema5 |
| Collector/notifier/integration-kode | `/opt/yggdrasil-sudo-integration`, commit `9ced7d60ab7b6776af95a12e83596683e04676ae` |
| Web med læstmarkering | `/opt/yggdrasil-nav-unread-web`, commit `614579ca2ab6fb246c363a8a95dc9a15a7135db3` |
| Privat sudo-sensor | `/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3`, schema2 |
| Frossen model | `sudo-if-15207a3b77b40fe2`, tærskel `0.6616139517267046` |
| Træningsgrundlag | 419 foreløbige normale virkelige observationer + 681 syntetiske normale observationer |

Port 8766 er det tidligere, manuelt startede preview. Den integrerede løsning
ligger på **8765**. Historiske sensorkandidater fra før aktivering overføres ikke
som nye produktionsalarmer. En kandidat, en ML-markering og en registreret alarm
er forskellige ting i visningen.

## Sidste driftsrettelse

Den oprindelige systemd-fil krævede en eksisterende ML-modelfil for overhovedet
at starte integrationsjobbet. Modelmappen var også et obligatorisk readonly-mount.
Det gjorde regelalarmer afhængige af en shadow-komponent.

`deploy/sprint5_sudo_production_finish_pi.sh` retter kun integrationsjobbets
systemd-fil: modelbetingelsen fjernes og modelmappens readonly-mount bliver
valgfrit. Python-jobbet håndterer allerede en manglende eller ugyldig model ved
at fortsætte regelimporten og eksportere ML som utilgængelig. Kørslen returnerer
en fejlkode ved utilgængelig ML; regelfund, alarm og outbox er da allerede
behandlet uafhængigt. Næste normale timerkørsel forsøger igen.

Kør wrapperen fra den gennemgåede Git-commit med commit-SHA som første argument.
Den kræver ovenstående installerede kildeversioner, aktive og aktiverede
produktionstjenester/timere og en sund eksisterende installation. Den afviser
uventede lokale unitændringer. Den er ikke en ny installation eller en generel
opgraderingskommando efter senere samling af `main`.

Forløbet er:

1. Kontroller adgang som worker, web og notifier samt frossen model og frisk kilde.
2. Gem den tidligere unit privat i
   `/var/backups/yggdrasil-ids/sudo-production-finish-before-<commit>`.
3. Udskift kun den kendte unit atomisk, og kør `systemctl daemon-reload`.
4. Vent højst 150 sekunder på et nyt sundt resultat fra den eksisterende timer.
5. Kontroller login, loginbeskyttet sudo-side, læstmarkering, offentlig eksport,
   privat dataadskillelse og match mellem notifierens og outboxens identitet.

Ingen tjenester genstartes, ingen ny testalarm fremkaldes, og der ændres ikke
database, model, konfiguration eller notifierens leveringshistorik. Et afbrud
efter unitudskiftningen kan afsluttes ved samme kommando igen. Fejl under
daemon-reload gendanner den tidligere unit; en senere fejlet sundhedskontrol
bevarer rettelsen og skriver STOP. Den gendanner aldrig en gammel database.

Afslutningsversion `11b565e683e9b12c12b146a770a3138e34c1d351` stoppede på
Pi'en med `Effective sudo unit still has a start condition`, efter at den nye
unit var gemt og genindlæst. Slutkontrollen behandlede enhver tekst fra
`systemctl show --property=Conditions --value` som en konfigureret betingelse.
Systemd's generiske formatter kan imidlertid vise `Conditions=[unprintable]`
for denne sammensatte datatype, også når listen er tom. Pi'ens konkrete rå
property-output blev ikke indsamlet, så STOP-beskeden alene dokumenterer ikke
den faktiske liste.

Den rettede kontrol henter den typede `a(sbbsi)`-liste via `busctl`. Kun svaret
`a(sbbsi) 0` accepteres; reelle betingelser, ukendt format og mislykket opslag
afvises. `LoadUnit` indlæser definitionen uden at starte jobbet. Genkør den nye
pinnede wrapper: den genkender den allerede opdaterede unit, bevarer den første
versions backup og fortsætter med en ny timerbaseret acceptkontrol. En
afbrudt afslutning kræver ingen databasereparation eller ny installation.

Datatypen er dokumenteret i [systemd's D-Bus-interface](https://www.freedesktop.org/software/systemd/man/257/org.freedesktop.systemd1.html).
Formatterens fallback findes i [systemd v257's kildekode](https://github.com/systemd/systemd/blob/v257/src/shared/bus-print-properties.c).
Det typed output er beskrevet i [busctl-manualen](https://www.freedesktop.org/software/systemd/man/257/busctl.html).

Samme wrapper med andet argument `check` udfører kontrol uden unitændring,
daemon-reload eller venten på et nyt timerresultat. Den kræver, at rettelsen
allerede er installeret. Kontrollen sender ikke beskeder til Discord og beviser
ikke ny levering; den tidligere live-test er leveringsbeviset.

## Normal drift og fejlsøgning

De tre sudo-timere er `yggdrasil-sudo-shadow.timer`,
`yggdrasil-sudo-ui-export.timer` og `yggdrasil-sudo-integration.timer`.
De skal være aktive og enabled. Deres services er oneshot-job og kan normalt
stå som `inactive` mellem kørslerne. Integrationen bruger en friskhedsgrænse på
180 sekunder; sensorens ældre oversigts-/aktivitetseksport bruger 300 sekunder.
Forældede resultater skal undersøges. En tom, frisk ML-periode er normal ved stilstand.

```bash
systemctl is-active yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
systemctl list-timers --all 'yggdrasil-sudo-*'
sudo journalctl --unit=yggdrasil-sudo-integration.service --lines=30 --no-pager
```

Ved sensorfejl kontrolleres også journalen for `yggdrasil-sudo-shadow.service`.
Ved eksportfejl kontrolleres `yggdrasil-sudo-ui-export.service`. Modelfejl må
ikke præsenteres som nul afvigelser. Webbrugeren skal fortsat være afskåret fra
den private sensor og modellen; giv ikke bredere filrettigheder for at løse en
visningsfejl. Workerens primære gruppe hedder **`yggdrasil-data`**.

Hvis en timer står som aktiv, men mangler friske resultater, undersøges fejlen
før flere testforsøg. Reparer fremad på schema5, når sudo-alarmdata er oprettet.
Gendan ikke en ældre database oven på den aktive historik, og nulstil ikke
notifieren. Sensoren beholder 30 dages normaliserede data; produktionsretention
følger den eksisterende konfiguration. Der påstås ikke fuldstændig dækning ved
journalrotation, længere udfald eller større klokkespring.

## Begrænsninger og eksamensbeviser

Reglerne finder gentagne autentificeringsfejl og sudoers-afvisninger. De
fastslår ikke, at et angreb lykkedes. En tilladt, skadelig sudo-kommando er ikke
automatisk dækket. Logningens proces-UID er heller ikke en verificeret identitet
for den person, der startede kommandoen. Brugernavne og kommandolinjer er ikke
gemt i denne sudo-visning.

ML-panelet viser op til 15 procespositioner fra de sidste 15 minutter. Resultater
genberegnes med løbende kontekst og kan ændres. Gamle proces-scores gemmes ikke
som uforanderlig historik. Anomaliscore er ikke angrebssandsynlighed.
Den blandede model har stadig kendte falske markeringer ved en rettet tastefejl
og dele af en normal serie med 60 processer. Derfor udløser reglerne alarmerne.

Den beståede live-test gav tre afviste processer, én regelkandidat, alarm **4**
og én bekræftet Discord-levering. ML markerede to af tre matchede processer i
shadow. Den tidligere, separate frosne prøve gav nul markeringer af 30 normale
processer og én af tre fejlede processer. Det er kontrollerede forløb, ikke
estimater af generel recall eller falsk-positiv-rate.

Gem disse skærmbilleder til rapport/bilag:

- Terminalens beståede live-test og den afsluttende driftskontrol, når den er kørt.
- Den registrerede sudo-alarm med tidspunkt, regel og tre processer.
- Den tilsvarende Discord-besked; reference `7ed92c291071761580e50cbbebbcfb39`.
- Sudo-sidens aktive regelintegration og ML-panelets modelversion, tærskel og shadow-status.

Tabellen nederst med syntetiske benchmarkresultater tilhører en separat,
historisk model. Den er ikke en måling af den aktive blandede models drift.

## Validering af afslutningen

Arbejdsserverens samlede kørsel bestod med 883 Python-tests og 9 Node-tests.
De samme 14 eksisterende worker-tests blev udeladt, fordi serveren kører som root
og ikke kan skifte brugeridentitet; deres produktionskontrol mod root er bevaret.
Ruff lint/formatering, Python- og shellsyntaks samt de indlejrede rolleprogrammer
er kontrolleret. Systemd validerede unitens syntaks med en lokal Python-sti som
erstatning for Pi'ens utilgængelige venv-sti; den eneste forskel fra den tidligere
installerede unit er de beskrevne modelafhængigheder. Det er forberedelse og
softwaretest; den afsluttende Pi-kontrol er endnu ikke dokumenteret som kørt.

Formatteringsrettelsen bestod derefter 890 Python-tests med de samme 14
udeladelser. De nye regressioner dækker den tomme typede liste, en reel
betingelse, ukendt eller manglende output, forkert unit-identitet og genkørsel
med den allerede opdaterede unit og den første backups bytes bevaret.
