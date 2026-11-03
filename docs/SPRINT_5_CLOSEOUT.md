# Sprint 5 – Sudo-overvågning: faglig afslutning før eksamen

**Dato:** 3. november 2026 (Europe/Copenhagen)  
**Status:** **Regelbaseret sudo-shadow-del afsluttet; sudo-Isolation-Forest-del under udvikling** på
Yggdrasil, Debian 13 på Raspberry Pi 5. Denne status omfatter **ikke**
automatisk sudo→Discord-alarm i produktion.  
**Kilde:** Udviklingsgren `integration/sprint5-sudo-clean`;
installeret sudo-shadow-kode er særskilt verificeret og pin'et til
`6b662fe07c85b2c4caa34129c8cac0f2146b9b80`.
Senere dokumentationscommits er ikke automatisk installeret på Pi'en.

## Målsætning

Tilføj en sikker, forklarlig sudo-sensor til Linux-serverens IDS, som
registrerer autentificeringsfejl og kendte afvisningsmønstre, uden at
ændre eksisterende SSH, UFW, Isolation Forest, dashboard eller Discord.
Afprøv en reel kontrolleret positiv detektion, normalaktivitet,
deduplikering, checkpoint/genstart, adgangsrettigheder og integritet.
Begræns kørsel på Pi til *shadow*, indtil der findes en særskilt,
godkendt alarm-/outboxintegration.

## Gennemførte testresultater

| Forsøg | Observeret resultat | Vurdering |
| --- | --- | --- |
| Isoleret Ubuntu-VM: tre kontrollerede fejlede sudo-processer | Historisk replay: **3 særskilte fejlede processer**, `sudo.repeated_auth_failure=1`, 0 parsefejl | **Bestået for replay** |
| Ubuntu-VM: ny live-test mod `journalctl --follow` | **21** parsebare sudo-poster, **1** regelkandidat, **21** unikke private SQLite-poster | **Bestået for live shadow** |
| Ubuntu-VM: samlet historisk preview | **72** sudo-poster, **2** kandidatfund for to adskilte kontrollerede serier | **Bestået for historik** |
| SQLite-outbox og notifier med falsk afsender | **2** midlertidige alerts → **2** outbox-events → **2** fake-leveringer, 0 afventende, 0 rigtige Discord-beskeder | **Bestået som isoleret integrationstest** |
| Pi: virkelig, tydeligt mærket `SUDO LABTEST`-notifikation | `real_discord_acknowledged=true`, systemd `SUCCESS` | **Bestået for rigtig levering af simuleret testevent** |
| Pi: normal `sudo /usr/bin/true` | 3 journald-poster fra en legitim kommando; ingen sudo-alarm | **Bestået** |
| Pi: checkpoint/replay | 3 først gemte sudo-poster, 3 dubletter ved anden poll, 0 nygemte | **Bestået** |
| Pi: manuel systemd-oneshot | `Result=success`, 54 normale sudo-poster lagret, 0 kandidater | **Bestået** |
| Pi: automatisk systemd-timer | `active` og `enabled`; checkpoint **2026-11-03 10:51:33 CET**; privat SQLite havde **69** poster og **0** kandidater | **Bestået for kortvarig periodisk drift** |
| Pi: sidste SQLite- og rettighedskontrol | **4/4** services/timer `active`; state-dir `0700`, SQLite `0600`, `PRAGMA integrity_check=ok`, **75** gemte sudo-poster, **0** kandidater, `RESULTAT: PASS` | **Bestået** |

Alle konkrete målinger er fra brugerens terminaloutput eller
direkte bekræftelse. Screenshots opbevares hos ejeren, og selve
billedfilerne er ikke gennemgået eller lagt i den offentlige repo.

## Funktion og arkitektur

- **Kilde:** journald-poster med kernel-verificeret
  `_EXE=/usr/bin/sudo`, fra alle journal-scope, uden `--system`.
- **Regler:** Tre særskilte fejlede sudo-PID'er for samme boot/UID inden
  for 300 sekunder; særskilt `not_in_sudoers`-klasse.
  PAM-autentificeringsfejl og efterfølgende forkert-password-summary
  fra samme PID tæller kun som **ét** forsøgsforløb.
- **Privat drift:** systemd-oneshot via `yggdrasil-sudo-shadow.timer`
  med omtrent et minuts interval, `yggdrasil-worker`, `PrivateNetwork=true`
  og en særskilt `/var/lib/yggdrasil-sudo-shadow/`-SQLite.
- **Genoptagelse:** Overlappende, bounded journalgenlæsning,
  transaktionel SQLite-deduplikering og watermark for fuldført poll.
  Den gamle Pi-collector/notifier/database ændres ikke.
- **Privatliv:** Ingen rå journald-cursors, kommandoindhold,
  passwords eller webhookværdier gemmes i sudo-shadow-databasen.

## Hvad vi ikke har bevist

En `sudo.repeated_auth_failure`-kandidat er en **regelbaseret
mistanke**, ikke en bekræftet kompromittering. Der er ikke en målt
produktions-FPR, 24-timers stabilitetstest, uafhængigt repræsentativt
normaldatasæt, eller fuldstændig tabsløs journald-recovery.
`sudo.permission_denied`-reglen har endnu ikke fået en kontrolleret
*positiv* praktisk VM-test. En automatisk **sudo→produktionens
`alerts`→Discord**-kæde er **ikke aktiveret**; den faktiske Discord-test
var et eksplicit mærket, syntetisk testevent i en separat outbox.

Isolation Forest på SSH forbliver eksperimentel i shadow-mode.
Den fungerende sudo-sensor i produktion er **regelbaseret**.
En særskilt **sudo-Isolation-Forest-prototype er tilføjet til
udviklingsbranchen**, men den er endnu ikke kørt og evalueret på Pi,
er ikke installeret som produktionsmodel og giver ingen alarmer.
Først efter en adskilt hold-out-evaluering må den beskrives
som testet.

## Relevante screenshot-kandidater

Se `docs/SCREENSHOT_CANDIDATES.md`.
Anbefalet prioritering til rapporten:
`S5-04` (to positive VM-sudo-regelfund),
`S5-10` (genstart/deduplikering),
`S5-11` (manuelt systemd-forløb) og
`S5-12` (timer, checkpoint og lagring).
`S5-07` (virkelig `SUDO LABTEST`-Discord-besked) viser alene
leveringsfunktion, **ikke** live angrebsudløst levering.
De tekniske resultater kan bruges, selv om et screenshot
ikke kom med, men verificér aldrig billeddetaljer uden at se filen.

## Stopbeslutning og fremtidigt arbejde

**Eksamensafgrænsning opdateret:** Færdiggør det allerede
planlagte **sudo-Isolation-Forest-eksperiment** og sammenlign
det med sudo-reglerne før projektfrysning.
Ingen yderligere sensorkilder (fx filintegritet) inden eksamen.
Brug derefter tiden på systemforståelse, unit tests,
regler kontra Isolation Forest, false positives,
metodekritik, diagram, udvalgte bilag og rapport.
Efter eksamen: undersøg filintegritetsovervågning (FIM)
og eventuelt en ny ML-model, hvis datamængde,
featurerepræsentation og uafhængig evaluering kan
understøtte den. En virkelig sudo-alarm til Discord
kræver en separat opt-in produktionsintegration
med rollback, test og kontrol af risiko for støj.
