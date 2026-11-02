# Sprint 3 · Skærmbilleder til eksamensrapporten

**Formål:** Dokumentér den eksperimentelle kæde fra kendt testtrafik til
journalindsamling, regelanalyse, alarm og Discord. Et screenshot er evidens
for netop det, man kan se; det er ikke en erstatning for tydelig metode,
målinger eller diskussion af begrænsninger.

## Prioriteret bilagsliste

| Bilag | Hvad bør vises | Hvornår | Status |
| --- | --- | --- | --- |
| S3-A | Ubuntu/WSL Nmap med tid, 10 porte `45010-45019` og `filtered` | Første scan, tærskel 6 | Kan tages af eksisterende terminaloutput |
| S3-B | Anonymiseret SQL-porttabel: 8 SYN / 5 unikke porte | Første scan, tærskel 6 | Kan tages af eksisterende terminaloutput |
| S3-C | Read-only aggregator med 5 unikke, 0 alarmer og sund collector | Første scan, tærskel 6 | Gem output/screenshot fra terminal, hvis tilgængeligt |
| S3-D | Udsnit af **kun** `[network]`-sektionen: `enabled=true`, `window_seconds=60`, `distinct_ports_threshold=5` | Efter kontrolleret tuning | Klar til screenshot: tuning bestået |
| S3-E | Yggdrasils private `/network`-side med registreret aktivitet | Efter anden scan kl. 00:53 | SQLite bekræftet; screenshot af dashboard afventer |
| S3-F | Alarmoversigt og evt. detaljer for `network.tcp_port_scan` | Anden scan kl. 00:53 | Alarm bekræftet; screenshot af dashboard afventer |
| S3-G | Faktisk Discord-besked med `Mulig TCP-portscanning (UFW)` og referencen | Anden scan kl. 00:53 | Discord-toast modtaget i samtalen – gem originalen privat |
| S3-H | Kort anonymiseret terminaludsnit af `systemctl is-active` og collector/netværksstatus | Efter ny test | Valgfrit |

**Anbefaling til en kort rapport:** Brug S3-B og sammenligningen
af før-/efter-tærskel i brødteksten, og læg Nmap, dashboard og Discord
som bilag. Beskriv skriftligt, at den første scanning var en kendt
positiv, som gav **0 alarmer ved tærsklen 6**; det må ikke ændres
retrospektivt. Nye alarmresultater med tærsklen 5 dokumenteres
som en **ny** selvstændig test.

## Praktisk capture og databeskyttelse

- Tag screenshot mens programnavn, måling og relevant tidspunkt er synligt.
- Anonymisér privat kilde-/destinations-IP på billeder, der skal
  offentliggøres. Bevar originale, uredigerede screenshots kun lokalt.
- Undgå screenshots af webhooks, credentials, hele `/etc/yggdrasil-ids`,
  private journalposter, sessionscookies og unødvendige brugernavne.
- Dashboardets alarm er kun et *muligt* scanningsmønster, ikke bevis
  for et egentligt angreb; Discord-kvittering er ikke det samme som
  en pushnotifikation på en bestemt telefon.
- Dokumentér tydeligt `UFW low` og at lograte-begrænsninger gør
  de registrerede pakker til et ufuldstændigt billede af trafikken.
- Gem screenshots i en privat mappe indtil gennemgang. Ingen upload
  til det offentlige GitHub-repo uden gennemført redaktion.

**Foreløbige bilagsnavne:** `S3-A-nmap-baseline.png`,
`S3-B-ufw-portfordeling.png`, `S3-C-tærskel6-ingen-alarm.png`,
`S3-D-netværkskonfiguration5.png`,
`S3-E-dashboard-netværk.png`,
`S3-F-portscan-alarm.png`,
`S3-G-discord-varsling.png`.

Skærmbillederne er **ikke oprettet af dette dokument**. Ejeren tager
dem på laptop/Pi under de relevante aktiviteter.

## Ny dokumenteret ændring – tag billedet nu

Ejeren har bekræftet `distinct_ports_threshold=5` på Pi, schema v4,
aktive IDS-tjenester og uændret UFW `low`. Gem **S3-D** enten som
et beskåret billede af kun `[network]`-konfigurationssektionen eller
terminalens PASS-meddelelser (uden adgangskoder).
Gem derefter **S3-E/S3-F/S3-G** i forbindelse med **en ny** scan,
hvis data, alarm og Discord-besked faktisk optræder.

Den nye tuning er en kalibrering efter test 1; S3-A/B/C skal vise
historiske resultater med tærskel 6 uændret, så rapporten ikke
forveksler trænings-/justeringsgrundlag med uafhængig evaluering.

## Anden Nmap-test – screenshotmulighed

Kl. **00:53 CET den 2. november 2026** blev den samme 10-porttest
kørt med tærskel 5. Alle porte var `filtered`; varigheden var 22,21 s.
Tag gerne et særskilt screenshot af denne Ubuntu-terminal og navngiv
det `S3-I-nmap-threshold5.png`. Det kan sammenlignes med første
Nmap-screenshot `S3-A-nmap-baseline.png`.

**S3-F og S3-G skal kun markeres som gennemført, hvis vi faktisk
bekræfter en alarm og en leveret Discord-meddelelse**. Beskær
eventuelle IP-adresser, private detaljer og logins før offentlig deling.

## Test 2 bestået – billeder til færdig rapport

Den anden Nmap-test udløste én portscanningsalarm (10
detektionsfund grupperet i 1 alarm) og én Discord-outboxpost.
Notifierens leverede antal steg **1 → 2** med `pending=0`.
Brugeren sendte et faktisk Discord-desktopnotifikationsbillede,
som viser `Mulig TCP-portscanning (UFW)`.

**Gem screenshotet lokalt som S3-G** (ikke offentlig GitHub-upload).
Tag nu **S3-F** med detaljerne for
`network.tcp_port_scan` på det private dashboard og **S3-E**
med registrerede firewallposter i `/network`, hvis de
fortsat er tilgængelige. Maskér IP-adresser og credentials
før rapportdeling. Det oprindelige 6-ports-miss forbliver
separat evidens som S3-A/S3-B/S3-C.

Foreslåede billedtekster:

- *Baseline: Scanning af ti TCP-porte gav ingen alarm ved
  seks-ports-grænsen, da kun fem unikke porte blev logget.*
- *Efter eksperimentel justering til fem porte oprettede
  IDS én alarm med ti tilknyttede detektionsfund.*
- *Discord modtog én automatisk portscanningsnotifikation;
  køen havde ingen ventende meddelelser.*

## Bilag S3-J – Graf over portaktivitet (efter live-installation)

Den nye `/network`-side er udviklet med to grafer: registrerede
blokerede TCP SYN-pakker over tid og de ti mest berørte
destinationsporte plus `Øvrige porte`.

**Screenshot S3-J** skal først tages efter en særskilt
live-installation og kontrol af graferne på Pi. Beskær til
graferne samt teksten om logdækning; undgå at vise IP-adresser
i hændelsestabellen i et offentligt rapportbilag.

Forslag til billedtekst:

*Visualisering af faktisk registrerede UFW-pakker.
De ti mest observerede destinationporte vises separat,
mens resten aggregeres. Grafen er ikke et komplet
billede af afsendte forbindelsesforsøg.*
