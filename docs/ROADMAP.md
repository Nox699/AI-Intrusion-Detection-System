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

**Status: Installeret på Pi med schema v4; live netværksindsamling endnu ikke aktiveret.**

Parseren og den eksperimentelle TCP-portscanningsregel er softwaretestet.
En separat `firewall_events`-historik, opt-in kernel-journalintegration,
TCP-scanningsalarmer med særskilt evidens og Discord-outbox samt en privat
`/network`-side er implementeret i skema v4. Den 1. november 2026 bestod en
kontrolleret migration **på en kopi** af Pi'ens schema-v3-database med
bevarede SSH- og Discord-data. En første 5-minutters måling fandt
15 kernelposter, alle UFW-poster; længere belastningsmålinger afventer.
Den 1. november 2026 bestod driftsmigrationen til schema v4, og alle tre
IDS-tjenester blev genstartet og kontrolleret med bevaret SSH-historik
og Discord-outbox. Kontrolleret netværksopt-in, scanningsevaluering og
langtidsaccept afventer. UFW `low` bevares indtil en særskilt
bevidst prøve.

[Arkitektur, dækningsgrænser og status](SPRINT_3_NETWORK.md) ·
[Pi-resultater](SPRINT_3_PI_RESULTS.md) ·
[Pi-opgraderingsplan](SPRINT_3_PI_DEPLOY.md).

## Backlog · prioriteres efter de første sprints

| Område | Mulig funktion | Afklaring før implementering |
| --- | --- | --- |
| Netværk og portscanning | Oversigt over observerede forbindelsesforsøg og scanmønstre. | Valg af logkilde, dækning og ratebegrænsning; antal firewallposter er ikke antal bots. |
| Administratorrettigheder | Analyse af sudo-hændelser og usædvanlige privilegerede handlinger. | Hvilke hændelser logges, hvad er forventet administration, og findes egnede normaldata? |
| Filintegritet | Registrering af ændringer i udvalgte vigtige filer. | Filvalg, forventede opdateringer og forskellen mellem ændringsregistrering og forklaring af årsagen. |
| Flere ML-modeller | Isolation Forest på andre meningsfulde aktivitetsfeatures. | Tilstrækkelige data, særskilte features og evaluering mod relevante regler. |
| Daglige og ugentlige oversigter | Samlet historik over alarmer, aktivitet og datakvalitet. | Rapportindhold, dataperiode og eventuel levering til Discord. |

Disse områder har endnu ikke sprintnumre eller lovede leveringsdatoer. Hver
udvidelse skal have et konkret mål, en kendt datakilde og kontrollerbare
acceptkriterier. Et domæne eller en offentlig webapp er ikke en forudsætning
for projektet, og testscenarier kræver ikke åbning af serveren mod internettet.
