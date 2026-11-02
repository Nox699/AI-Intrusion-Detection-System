# Roadmap

Projektet udvikles i afgrænsede sprints. En implementeret funktion og en bestået
softwaretest er adskilt fra accepttest på den faktiske server. Planen nedenfor
beskriver den aktuelle status; den er ikke en historik over tidligere releases.

## Sprint 1 · SSH-overvågning

**Status: Implementeret og softwaretestet. Pi-accepttest afventer.**

Leverancen omfatter journalindsamling, fortolkning af SSH-autentificeringer,
konfigurerbare regler, Isolation Forest, SQLite-historik og et privat dansk
webdashboard. Collector og dashboard kører som separate tjenester. Demo,
syntetisk laboratorieforsøg, tests og installationsvejledning følger med.

Før sprintet kan accepteres på målsystemet, skal [Pi-accepttesten](TEST_ON_PI.md)
bekræfte de faktiske logformater, servicekontienes rettigheder, genstart uden
dubletter, backup/restore og målt svartid. Ressourceforbrug og fejl følges over
mindst 24 timers drift. Et tilstrækkeligt normaldatagrundlag skal opbygges før
modellens detektionskvalitet kan vurderes i det konkrete miljø.

[Verifikationen](VERIFICATION.md) beskriver, hvad der allerede er afprøvet,
og hvilke begrænsninger resultaterne har.

## Sprint 2 · Discord-notifikationer

**Status: Sprint 2-funktionalitet færdig og praktisk demonstreret på Pi. Langtidsdrift og særskilte sikkerhedstests følges op.**

En separat systemd-notifier sender nye udvalgte alarmforløb fra en SQLite-
outbox til en privat Discord-kanal via HTTPS-webhook. Den kører uafhængigt af
collectoren og har separat leveringsstatus. En kontrolleret ny preauth-alarm
blev vist i dashboardet og udløste en Discord-desktopnotifikation på brugerens
computer. Mobil-push er endnu ikke særskilt dokumenteret.

[Praktiske Pi-testresultater og begrænsninger](SPRINT_2_PI_RESULTS.md) og
[afslutningskontrol](SPRINT_2_CLOSEOUT.md).

- Konfiguration af webhook og alarmniveau uden hemmeligheder i Git eller logtekst.
- Korte beskeder med hændelsestype, tidspunkt og begrundelse; begrænset deling af
  IP-adresser, brugernavne og rå logs.
- Gruppering og begrænsning af gentagne beskeder samt kontrollerede genforsøg.
- Synlig leveringsstatus; en netværksfejl må ikke stoppe logindsamlingen.
- En særskilt notifierkomponent, så collectorens begrænsede netværksadgang kan
  bevares. Den konkrete proces- og rettighedsmodel fastlægges i sprintet.

En kontrolleret Discord-testbesked og en automatisk besked fra en reel IDS-
regelalarm er leveret. Simulerede transportfejl og genstart er afprøvet i tests.
Fuld accept afventer bl.a. fejltest på Pi, rettighedsrevision, outbox-retention,
fuld maskingenstart og dokumenteret drift under belastning.

## Sprint 3 · UFW-observation og mulig TCP-portscanning

**Status: Funktionelt afsluttet på Pi den 2. november 2026. UFW-indsamling, TCP-scanning, Discord og browsergrafer er demonstreret; længere FP-/stabilitetsevaluering udestår.**

Parseren og den eksperimentelle TCP-portscanningsregel er softwaretestet.
En separat `firewall_events`-historik, opt-in kernel-journalintegration,
TCP-scanningsalarmer med særskilt evidens og Discord-outbox samt en privat
`/network`-side er implementeret i skema v4. Den 1. november 2026 bestod en
kontrolleret migration **på en kopi** af Pi'ens schema-v3-database med
bevarede SSH- og Discord-data. En første 5-minutters måling fandt
15 kernelposter, alle UFW-poster; længere belastningsmålinger afventer.
Den 1. november 2026 bestod driftsmigrationen til schema v4, og alle tre
IDS-tjenester blev genstartet og kontrolleret med bevaret SSH-historik
og Discord-outbox. UFW-opt-in er gennemført med logniveau `low`.
Første Nmap-test gav ingen alarm ved tærskel 6; efter
kalibrering til 5 gav en anden kontrolleret test én alarm
og én leveret Discord-besked. Normaldrift, falske positiver,
langtidsstabilitet og performance mangler stadig.

[Arkitektur, dækningsgrænser og status](SPRINT_3_NETWORK.md) ·
[Pi-resultater](SPRINT_3_PI_RESULTS.md) ·
[Pi-opgraderingsplan](SPRINT_3_PI_DEPLOY.md).

## Sprint 4 · AI, Isolation Forest og dokumenteret evaluering

**Status: Forberedelse og tests på udviklingsbranch; Pi-labafprøvning afventer.**

Dette sprint er prioriteret før sudo og filintegritet for at sikre, at AI-
eksamensopgavens centrale ML-versus-regler-evaluering kan fremvises.
Et eksisterende syntetisk SSH-laboratorium træner Isolation Forest på
312 normale observationer og evaluerer på selvstændige 44 validerings-
og 41 sluttesthændelser. Vi har nu tilføjet en særskilt audit af
produktionsdata og en verifier, der kontrollerer SHA-256, datasplit
og confusion-matricer, før metrikker bruges i rapporten.
Kun aggregerede tal forlader laboratoriet; ingen private logs eller
modelartefakter uploades automatisk til GitHub. På Pi er modellen
stadig `untrained` (12 SSH-observationer mod minimum 80).

[Sprint 4 – metode og accept](SPRINT_4_AI_EVALUATION.md) ·
[Runbook til Pi](SPRINT_4_PI_RUNBOOK.md) ·
[Træningsplan og databegrænsninger](ML_PI_TRAINING_PLAN.md).

## Sprint 5 · Sudo/privilegier (planlagt)

**Status: Afventer Sprint 4/eksamensprioritering.**

Betroede sudo-/PAM-hændelser, forklarlige privilegie-regler,
alarmgruppering, tests og eventuel Discord-varsling.
En særskilt ML-model til sudo kræver et nyt, varieret normalt
datagrundlag og må ikke arve SSH-modellens score ukritisk.

## Sprint 6 · Filintegritet og samlet driftsoversigt (planlagt)

**Status: Afventer; plan om afgrænset file integrity monitoring.**

Overvåg udvalgte konfigurationsfiler med kendt baseline,
hashes/metadata og tydelig håndtering af forventede opdateringer.
Efterfølgende opsummering og slutaccept omfatter daglig/ugentlig
sikkerhedsrapport, tests, begrænsninger og eventuel Discord-levering.
Arbejdet skal ikke forsinke AI-eksamensrapportens centrale resultater.

## Backlog · prioriteres efter de første sprints

| Område | Mulig funktion | Afklaring før implementering |
| --- | --- | --- |
| Netværk og portscanning | Oversigt over observerede forbindelsesforsøg og scanmønstre. | Valg af logkilde, dækning og ratebegrænsning; antal firewallposter er ikke antal bots. |
| Administratorrettigheder | Analyse af sudo-hændelser og usædvanlige privilegerede handlinger. | Hvilke hændelser logges, hvad er forventet administration, og findes egnede normaldata? |
| Filintegritet | Registrering af ændringer i udvalgte vigtige filer. | Filvalg, forventede opdateringer og forskellen mellem ændringsregistrering og forklaring af årsagen. |
| Flere ML-modeller | Isolation Forest på andre meningsfulde aktivitetsfeatures. | Tilstrækkelige data, særskilte features og evaluering mod relevante regler. |
| Daglige og ugentlige oversigter | Samlet historik over alarmer, aktivitet og datakvalitet. | Rapportindhold, dataperiode og eventuel levering til Discord. |

Sprint 4–6 er nu nummereret; andre mulige udvidelser forbliver
backlog uden lovet leveringsdato. Hver udvidelse skal have et konkret mål,
en kendt datakilde og kontrollerbare acceptkriterier. Et domæne eller en offentlig webapp er ikke en forudsætning
for projektet, og testscenarier kræver ikke åbning af serveren mod internettet.
