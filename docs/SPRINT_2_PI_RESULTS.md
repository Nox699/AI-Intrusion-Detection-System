# Sprint 2 · Praktiske testresultater på Yggdrasil

**Dato:** 1. november 2026 (Europe/Copenhagen)  
**Testmiljø:** Raspberry Pi 5, Debian 13, ARM64, Python 3.13  
**Installeret kildecommit:** `871eef2c951d402c29f3cf3796cb5b4b32baf209` på `sprint-2/discord-restart`  
**Status:** Sprint 2's centrale funktion er praktisk testet. Restkontroller nedenfor er særskilt opfølgning.

Resultaterne nedenfor bygger på brugerens terminaludskrifter og screenshots
under den praktiske installation. Der er ikke indsamlet adgangsnøgler,
webhook-tokens eller uanonymiserede loglinjer i repositoryet.

## Bekræftede observationer

| Kontrol | Metode og observeret resultat | Vurdering |
| --- | --- | --- |
| Før-opdateringsbackup | Konsistent SQLite-backup; `PRAGMA integrity_check=ok`, skema 2, ét eksisterende alarmforløb, mode 600 og root-ejer | Bestået |
| Migration på kopi | Faktisk driftsbackup kopieret til midlertidig database; skema 2 → 3; `integrity_check=ok`, ét alarmforløb før og efter, ingen retroaktivt oprettede notifikationsposter | Bestået |
| Kilde og installation | Pi hentede commit `871eef2`, byggede en wheel og installerede med `--force-reinstall --no-deps --no-index` efter at have stoppet IDS-tjenesterne | Bestået |
| Opdatering af driftsdatabase | Skema 3; `integrity_check=ok`; det tidligere alarmforløb bevaret | Bestået |
| Eksisterende tjenester | Collector og privat webdashboard var `active` efter opdateringen | Bestået |
| Discord engangstest | En testbesked med tydelig angivelse af, at den ikke var en alarm, blev vist i den valgte Discord-kanal via testtjenesten | Bestået |
| Ny reel regelalarm | Et kontrolleret forløb med gentagne SSH-afbrud før login udløste et nyt `ssh.preauth_burst`-alarmforløb med niveau medium, synligt ved siden af den tidligere alarm i dashboardet | Bestået |
| Automatisk Discord-levering | Brugerens screenshot viste Discords desktopnotifikation fra Yggdrasil IDS samtidig med det nye alarmforløb | Bestået |
| Leveringsstatus | `pending=0`, `delivered=1`, `last_seq=1`, `cooldown_seconds=0` | Bestået |
| Tjenesteopsætning | `yggdrasil-notifier.service` blev `enabled`; collector, web og notifier var alle `active` | Bestået |
| Genstart af notifier | Notifieren blev genstartet med `systemctl restart`. Brugeren bekræftede, at resultatet så korrekt ud, efter kontrol af aktiv-status og leveringsmarkør | Bekræftet af bruger; fuld ny udskrift ikke indsamlet |

**Skel mellem observation og konklusion:** Discords testbesked og den
automatiske alarm blev faktisk vist på brugerens computer.
Det bekræfter denne leveringskæde, men dokumenterer ikke, at en mobiltelefon
modtog en pushnotifikation. En leveret alarm er heller ikke et bekræftet angreb.

Den tidligere preauth-alarm blev ikke sendt retroaktivt som ny Discord-alarm
ved notifierens første start. Det stemmer med outboxens forventede
første-aktiveringsadfærd, men er ikke en bredere test af alle migrationsscenarier.

## Automatiserede tests

GitHub Actions for den installerede kildeversion:
https://github.com/Nox699/AI-Intrusion-Detection-System/actions/runs/41266740493

Status: gennemført med succes på Linux med Python 3.11 og 3.13, herunder
Ruff-kontrol, formatkontrol, pytest og wheel-build.

Senere sikkerhedsregressioner for webhook, redirects, Discord-acknowledgement
og grupperede notifikationer bestod i GitHub Actions
https://github.com/Nox699/AI-Intrusion-Detection-System/actions/runs/41271766875
(kildecommit `c82f5dbac66a12081527d41e0cefe1edca290918`).
Denne nyere kode er udviklingsgrenens tilstand og skal installeres på Pi
separat, før dens konkrete drift dér kan erklæres testet. De automatiserede
notifier-tests anvender falske/modellerede Discord-svar og en lokal SQLite-
database; de er ikke tests af Discords driftsinfrastruktur.

## Resterende accept og begrænsninger

- **Fuld genstart af Raspberry Pi:** `enabled` og genstart af én systemd-tjeneste
  er verificeret. En egentlig maskingenstart er endnu ikke dokumenteret.
- **Fejlscenarier på målmaskinen:** ugyldig/slettet webhook, DNS-/netværksfejl,
  ratebegrænsning og langvarig Discord-udfald er afprøvet i kode/tests,
  men ikke dokumenteret under en kontrolleret Pi-driftsøvelse.
- **Rettighedsrevision:** notifierens separate systemkonto blev bekræftet med
  grupperne `yggdrasil-notifier` og `yggdrasil-data` (ikke
  `systemd-journal`). En faktisk læsning af alarmtabellen fandt to
  alarmforløb, mens forsøg på at åbne kildedatabasen med skriverettighed
  blev afvist. Journallæseadgang og hele systemd-sandboxen kræver stadig
  særskilt negativ kontrol på målmaskinen.
- **Belastning og retention:** ingen målinger af mange samtidige alarmer,
  diskforbrug over lang tid eller varig outbox-vedligeholdelse; outboxposter
  bevares for at undgå stiltiende datatab og kræver fremtidig retentionpolitik.
- **Leveringsgaranti:** webhooks kan ikke love præcis én leverance; et nedbrud
  efter Discord har modtaget beskeden, men før lokal kvittering er gemt,
  kan give en dublet ved genforsøg.
- **Observerbarhed:** CLI-status viser afventende og leverede beskeder samt
  cooldown. En komplet sundhedsvisning med seneste fejl, stale heartbeat
  og kapacitetsalarmer er endnu ikke implementeret.
- **Måling:** ingen reproducerbart målt forsinkelse fra journalhændelse til
  Discord-acknowledgement eller 24-timers stabilitetstest.
- **Sikkerhed:** Ingen ændringer er foretaget i SSH-, UFW-, Fail2ban- eller
  Tailscale-konfiguration som en del af Discord-integrationen.

## Rapportdokumentation

Gem separat (ikke som rå credentials i Git) et anonymiseret screenshot af
IDS-alarmoversigten og Discords automatiske notifikation i samme billede.
Det er stærkt bevis for en reel end-to-end-integrationstest. Notér særskilt,
at den første testbesked alene afprøvede forbindelsen til webhooken.

Et brugbart kildekodeuddrag til eksamensrapporten er den transaktionelle
SQLite-outbox: en ny alarm i `alerts` får en outbox-post i samme transaktion,
og notifieren læser den via en separat konto. Beskriv samtidig risikoen for
dubletten ved et nedbrud mellem netværkslevering og lokal kvittering.
