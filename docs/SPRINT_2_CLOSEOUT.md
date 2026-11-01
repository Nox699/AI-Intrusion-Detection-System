# Sprint 2 · Afslutningskontrol og drift

**Mål:** Bekræft at den installerede Discord-notifier fortsat virker sikkert,
uden at provokere nye SSH-fejl eller ændre adgangskontrol.

**Status:** Den centrale funktion er allerede demonstreret på Raspberry Pi.
Disse kontroller lukker den praktiske afleveringsdel. De resterende
langtids-/belastningsscenarier er eksplicitte begrænsninger, ikke beståede tests.

## Dokumenteret i forløbet

- Root-ejet webhookfil med mode `0600`; systemd leverer hemmeligheden til en
  særskilt notifierkonto gennem `LoadCredential`. Ingen webhook-URL i Git.
- Collector, privat webserver og notifier var alle aktive, og notifieren blev
  aktiveret med `systemctl enable`.
- En ægte testbesked i en privat Discord-kanal blev vist.
- Et nyt regelbaseret `ssh.preauth_burst`-alarmforløb blev vist i dashboardet
  og udløste en desktopnotifikation fra Discord.
- Leveringsdatabasen viste `pending=0`, `delivered=1`, `last_seq=1`,
  `cooldown_seconds=0` efter alarmen.
- Brugerens efterfølgende notifiergenstart så korrekt ud, men rå output
  fra den seneste statuskontrol blev ikke gemt i rapporten.
- Den særskilte notifierkonto kunne læse to alarmer men kunne ikke åbne
  driftsdatabasen med skriverettigheder.
- Backup og skema 2→3-migration blev afprøvet på en kopi, og databasens
  integritet forblev `ok`. Ved faktisk opdatering var tidligere alarm bevaret.

Se [målinger og forbehold](SPRINT_2_PI_RESULTS.md) for detaljer.

## Sidste sikre kontrol på Pi

Behold en åben, legitim SSH-session. Kør som din almindelige Pi-bruger:

```bash
printf 'Tjenester:\n'
systemctl is-active yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
printf 'Opstart:\n'
systemctl is-enabled yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
printf 'Notifierkontoens grupper:\n'
id -nG yggdrasil-notifier
printf 'Notifierstatus:\n'
sudo -u yggdrasil-notifier /opt/yggdrasil-ids/venv/bin/yggdrasil-ids notify \
  --config /etc/yggdrasil-ids/config.toml \
  --state-file /var/lib/yggdrasil-notifier/delivery.sqlite3 --status
printf 'Beskyttelse og ressourcer:\n'
systemctl show yggdrasil-notifier.service \
  -p NoNewPrivileges -p ProtectSystem -p PrivateDevices \
  -p MemoryCurrent -p TasksCurrent
```

Forventet: tre gange `active`, tre gange `enabled`, en notifiergruppe uden
`systemd-journal` og `adm`, en vellykket JSON-status med `pending=0`,
og en aktiveret systemd-sandbox. `delivered` må gerne stige, når **nye**
alarmer siden sidste kontrol faktisk er blevet leveret. De her kommandoer
ændrer ikke noget, udløser ingen alarm og viser ikke webhooken.

Et ekstra sikkert negativt tjek, hvis nødvendigt: journaladgangen skal kontrolleres
ud fra servicekontoens grupper **og** journalfilers faktiske adgangskontrol.
At en `journalctl`-kommando ikke udskriver hændelser er ikke i sig selv et
bevis på manglende rettigheder.

Hvis notifieren fejler:

```bash
systemctl status yggdrasil-notifier.service --no-pager
sudo journalctl -u yggdrasil-notifier.service -n 30 --no-pager
```

Vis aldrig indholdet af `/etc/yggdrasil-ids/discord-webhook.url` i
terminalevidens, supportchats eller screenshots.

## Vedligeholdelse og rollback

Notifieren skriver sin leveringsstatus i `/var/lib/yggdrasil-notifier/`.
Den lokale IDS-collector skriver til
`/var/lib/yggdrasil-ids/events.sqlite3`. Begge dele og en kopi af
`/etc/yggdrasil-ids/config.toml` bør indgå i backupstrategien;
webhookfilen skal opbevares separat med sikre rettigheder.

Den installerede pakke bruger stadig versionsnummer `0.1.0` selv om Git
udvikles videre. Notér derfor **commit-ID, wheel-hash og databaseversion**
ved hver installation. Ved tilbageførsel over databaseskemaer må den gamle
pakke ikke startes mod en inkompatibel ny database. Gendan en tilsvarende
databasebackup, hvis det er nødvendigt, med stoppet collector.

En rettelse til notifierkoden må ikke få `main` eller Pi-installationen
opdateret automatisk. Anvend verificeret commit og CI, byg i en ren
ikke-root-ejet midlertidig mappe og kontroller alle tre tjenester efter
opdateringen.

## Kendte begrænsninger og senere driftstest

1. En Discord-kvittering beviser ikke, at telefonen har vist en pushnotifikation.
2. Exactly-once-levering kan ikke garanteres: crash efter Discord-ack men før
   lokal commit kan give en dublet.
3. Outboxen har ingen automatisk retention/kvote. Den bevares for ikke at tabe
   beskeder lydløst, men diskforbrug skal overvåges. En sikker, koordinet
   retentionpolitik kræver senere designarbejde.
4. Fuldt host-reboot, 24 timers målt drift, stort antal samtidige alarmer,
   reproducerbar forsinkelse og kontrolleret netværksudfald på Pi er
   endnu ikke dokumenteret som bestået.
5. Gennemtest af negative journalrettigheder og fejlstatus for
   langvarigt utilgængelig Discord er fortsatte hardening-opgaver.
6. Grafens punkter og stiplede forbindelser er visuelle hjælpemidler og
   dokumenterer ikke netværksaktivitet mellem datapunkterne.

**Sprint 2-aflevering:** En fungerende, separat og privat Discord-integration
med testet SSH→alarm→Discord-kæde og automatisk opstart. Ingen påstand om
produktionscertificering eller fuldstændig driftsaccept.
