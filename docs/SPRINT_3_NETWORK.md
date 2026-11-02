# Sprint 3 · Firewallhændelser og mulig TCP-portscanning

## Status og grænser for denne leverance

**Udviklingsbranch:** `sprint-3/network-monitoring`, startet fra Sprint 2-merge
`63ea44a5363403b6da0725a894e48ea9a40a8bd7`.

**Første del:** isoleret UFW-parser og ren detektionsfunktion med tests.
**Anden del:** opt-in UFW-logindsamling til separat SQLite-tabel i skema v4,
med migration, transaktionel cursor, dubletkontrol, retention og backup.
**Tredje del:** den afgrænsede TCP SYN-detektor kan nu skabe
`network.tcp_port_scan`-alarmer, gruppere fund og indsætte en
Discord-outboxpost pr. nyt alarmforløb. Dashboardet har en privat
`/network`-side med pakketal, kilde/protokol-filtre og tydelige
logningsbegrænsninger. Netværksalarmer er integreret med alarmdetaljer
uden at oprette falske SSH-events eller ML-data.

**Bekræftet på Pi:** Schema 3→4 i drift med bevaret SSH-/Discord-historik, alle tre tjenester aktive og første UFW opt-in gennemført. En normaliseret firewallpost er gemt med UFW low. **Afventer:** en kontrolleret scanning, alarm/Discord-accept og 24h stabilitet.
Netværksindsamling er stadig `enabled=false` som standard. Denne
udviklingsversion må ikke aktiveres i driften uden kontrolleret
backup, migration og opt-in. `main` ændres ikke.

Der ændres ingen UFW-regler eller logniveauer. UFW forbliver på `low` under
udviklingen. En eventuel senere prøve med `medium` kræver en bevidst handling
på målmaskinen; dette bliver ikke udført af IDS-koden.

## Tredje del: live regler, alarmer og dashboard

Når netværksindsamling eksplicit er aktiveret, beregnes et TCP SYN-vindue
fra allerede gemte `firewall_events`, med samme gruppering af
namespace, boot, host, kilde, destination og indgående interface.
Kun **nye destinationsporte** kan producere et nyt scanfund:
gentagne pakker til en kendt port øger ikke alarmens antal.
For sene/fremtidige poster gemmes hændelsen, men der foretages ingen
retroaktiv alarmering. Historikoverløb giver `network_analysis_error`
i database-state frem for et tvivlsomt normalresultat.

`network_evidence` er separat fra SSH-`findings` og
`preauth_evidence` og bruger en unik
`(event_id,detector_id)`-nøgle. Fund fra den samme destination,
interface og sensor grupperes efter cooldown; nyt forløb opretter ét
alert og derved én transaktionel Discord-outboxpost.
En senere post inden for cooldown opdaterer forløbet, ikke
Discord-outboxen. Ved oprydning slettes forældet evidens og
alarmernes resterende antal/tidspunkter genberegnes.

Den autentificerede read-only side `/network` viser registrerede
firewallpakker, kilde, destination, port, protokol, interface og
paginering. Den advarer, hvis netværksindsamling ikke er aktiveret,
og om at UFW-logning kan være ratebegrænset. Alarmdetaljer
linker til netværkshistorikken for samme kilde i stedet for
at påstå, at der er tale om SSH-forsøg.
Discord-beskeden siger kun `Mulig TCP-portscanning (UFW)`,
tidspunkt og intern hændelsesreference, ikke kilde-IP, MAC eller rå log.

CI-testene dækker nye fund, gruppede forløb, flere destinationer,
genafspilning, rollback ved fejlet SQLite-write, deletion/retention,
webadgangskontrol og at rå IP-data ikke står i Discord-teksten.
Desuden testes migration mod en **kopi af det faktiske SQL-skema v3**
fra Sprint 2 i `tests/fixtures/schema_v3.sql`, frem for kun en
simuleret nedgradering af skema v4. Kildeskemaet indeholder
ingen private logposter.

## Anden del: opt-in journalintegration og database

`AppConfig.network.enabled` er **false** som standard. Uden opt-in bevarer
`journalctl` det eksisterende SSH-filter fuldstændigt, og kernelposter
indsamles ikke. En senere eksplicit `[network] enabled=true` tilføjer
`+ _TRANSPORT=kernel`, dvs. et separat OR-match uden at svække
`_UID=0`-kravet for SSH-processerne. Kun genkendte UFW-poster gemmes som
normaliserede firewallobjekter; ikke-UFW kernelposter lægges ikke i
`records`-tabellen. De passerer dog gennem journalstrømmen og checkpointet,
så kernel-logmængde og I/O skal måles, inden driftsaktivering.

SQLite-skema **4** tilføjer `firewall_events`, med unikke
`event_id`-nøgler og indeks efter tidsstempel og kildedimensioner.
Tabellen er adskilt fra `events`, `observations`, `findings`,
`preauth_disconnects` og Discord-outbox. Dette var status ved afslutningen af **trin 2**, hvor TCP-scanningsdetektoren
endnu ikke kørte i live collectoren. I **trin 3** er regler, alarmer og
Discord-outbox integreret bag eksplicit opt-in, som beskrevet ovenfor.

Firewallpost og journalcursor skrives i **samme transaktion**; en fejlet
SQLite-skrivning skal rulle både post og checkpoint tilbage, så journalposten
kan genindlæses. Ved første aktivering i live mode gemmes et starttidspunkt,
og ældre kernelhistorik springes over. Det modvirker historisk backfill og
en strøm af gamle netværksalarmer ved første opstart; SSH-forløb bevarer
deres tidligere checkpoint.

`Repository.firewall_history` er tidsvindue- og størrelsesbegrænset
og adskiller kilder, destinations-IP, interface, host, boot og namespace.
`Repository.prune` sletter også forældet firewallhistorik efter samme
retention som SSH; den eksisterende SQLite-backup omfatter tabellen.
De automatiske tests verificerer migrering af v3-data, bevaret SSH-alarm og
Discord-outbox-identitet, dubletafvisning, rollback og adskillelse fra
SSH-ML. Disse softwaretests er **ikke** en Pi-migration eller live scan-test.

**Driftssikkerhed:** Den 1. november 2026 bestod en migration af en
produktionsbackup **på kopi** (v3 → v4), og den første 5-minutters optælling
viste 15 kernelposter, alle med UFW-præfiks. Den faktiske driftsdatabase er
ikke migreret. Diskbudget, installeret kilde/wheel, tilbageførsel og
kontrolleret drift med netværksindsamling skal stadig godkendes. Ingen
ændring af UFW's logniveau eller firewallregler er nødvendig for denne
implementeringsdel. Se [Pi-resultater](SPRINT_3_PI_RESULTS.md).

## Datagrundlag

Ejeren har vist kernel-journalposter med `[UFW BLOCK]`, både som root og som
`yggdrasil-worker`. De indeholder bl.a. UDP til en lokal destination og
`PROTO=2` til multicast. Det dokumenterer adgang til denne logkilde, ikke at
alle pakker bliver logget, eller at der foregår scanning.

`tests/fixtures/ufw_journal.jsonl` indeholder fire testposter:

- To format-eksempler fra de viste UDP/IGMP-poster, med udskiftede adresser,
  MAC-værdier, journalidentiteter og tidspunkter.
- To syntetiske TCP SYN-poster (IPv4 og IPv6). De er ikke indsamlet på Pi'en.

Dokumentationsadresser er ikke produktionsadresser. Ingen MAC-adresser,
brugernavne, Discord-webhooks eller rå produktionslogs fra ejeren publiceres.

## Implementeret parser: `firewall.py`

`UFWParser.parse(record, namespace)` returnerer `event`, `ignored` eller
`malformed`, en begrundelse uden rå logindhold og eventuelt et `FirewallEvent`.

Parseren kræver journalfeltet `_TRANSPORT=kernel`. Et `SYSLOG_IDENTIFIER` med
værdien `kernel`, `_UID=0` eller en tekst med `[UFW BLOCK]` er ikke tilstrækkeligt.
Kernelposter behøver til gengæld ikke have `_COMM` eller `_UID`, som SSH-poster
har. Proveniens gælder data hentet direkte fra den betroede journal; den kan
ikke attestere en vilkårlig JSON-fil eller en kompromitteret root-konto.

De fortolkede felter omfatter IP-adresser, IP-version, protokol, porte når de
findes, ind-/ud-interface, retning, UFW-præfiks, tidsstempel, cursor og TCP-flag.
IPv6-adresser normaliseres. MAC og rå meddelelsestekst kopieres ikke ind i
hændelsesobjektet. Hændelses-ID er afledt af navnerum, kildetype og journalcursor,
så samme post kan genkendes ved genafspilning.

Vigtige formatdetaljer:

- UDP kan have både IP-længde og UDP-længde med feltet `LEN`. Begge bevares i
  hver sit felt; gentagne identitetsfelter som `SRC`, `DST` og `DPT` afvises.
- Numeriske protokoller understøttes, herunder `PROTO=2` → IGMP. Protokoller
  uden understøttet portsemantik får `None`, ikke en opfundet port 0.
- TCP/UDP-poster uden portpar kan registreres (fx fragmenter), men kan ikke
  bidrage til en portbaseret regel. Kun én af `SPT`/`DPT` er en formatfejl.
- Indgående, udgående og videresendt trafik holdes adskilt via `IN` og `OUT`.
- `ALLOW` og `AUDIT` bliver ikke omdøbt til `BLOCK`.
- Kontroltegn, ugyldige adresser/tidspunkter, tvetydige felter, manglende
  cursor og for store meddelelser afvises. Indlejrede ICMP-headerdump er
  bevidst ikke understøttet i denne første version.

## Implementeret regel: `network_rules.py`

`TCPPortScanDetector.evaluate(event, history)` undersøger et afgrænset
hændelsesvindue og returnerer højst ét `NetworkFinding` for den aktuelle post.
Det ændrer ikke filer, database, firewall eller netværk.

Den eksperimentelle standardgrænse er **seks forskellige destinationsporte
inden for 60 sekunder**, med følgende afgrænsning:

1. Kun indgående logposter med `BLOCK`, `REJECT` eller `LIMIT BLOCK`.
2. Kun TCP SYN uden ACK, RST eller FIN og med en kendt destinationsport.
3. Samme kilde-IP, destinations-IP, indgående interface, sensor, boot og
   datanavnerum. Porte fra forskellige værter lægges ikke sammen.
4. Gentagne journal-ID'er tælles kun én gang. Gentagne pakker og ændrede
   kildeporte til samme destinationsport øger ikke antallet af forskellige porte.
5. Vinduet er `(aktuel tid - vindue, aktuel tid]`. Ældre og fremtidige poster
   i den leverede historik tæller ikke med.
6. Multicast, begrænset IPv4-broadcast, loopback og uspecificerede adresser
   bidrager ikke. Private unicast-adresser bliver ikke automatisk undtaget.

Resultatet hedder **Mulig TCP-portscanning**, med niveau `medium`. Det angiver
antal registrerede pakker, forskellige porte, tidsvindue og konkrete
journalhændelses-ID'er. Evidenslisten begrænses til 64 porte, mens det samlede
antal stadig vises præcist og afkortning markeres. Historikgrænsen er 10.000
poster som standard; overskridelse giver en datakvalitetsfejl, ikke et falsk
resultat om normal aktivitet.

Grænsen er et startpunkt for afprøvning, ikke en dokumenteret statistisk optimal
værdi. Et fund er et observeret mønster, ikke bevis for et angreb, en bot eller
en bestemt person. UDP-, ACK-, FIN- og langsomme/distribuerede scanninger er
ikke dækket af denne første regel.

## Automatiske kontroller

De nye testmoduler er `tests/test_firewall.py` og `tests/test_network_rules.py`.
De kontakter ikke en rigtig server eller Discord og ændrer ikke UFW.

```bash
python -m pytest tests/test_firewall.py tests/test_network_rules.py
```

Testene omfatter de anonymiserede format-eksempler, IPv4/IPv6, manglende porte,
proveniens, fejlformater, grænseværdier, tidsvinduer, dubletter, forskellige
kilder/destinationer, gentagne pakker, UDP/multicast, TCP-flag og afgrænset evidens.

En bestået isoleret test er ikke en live-accepttest eller en test af netværkets
fulde synlighed. Den eksisterende projekttestsuite skal desuden forblive grøn.

## Implementeringskrav og resterende accept

De første seks punkter nedenfor er implementeret og softwaretestet på
udviklingsbranchen. Den sidste kontrollerede Pi-afprøvning er endnu ikke udført.

- Tilføj en eksplicit, deaktiverbar netværkssektion i konfigurationen med
  validerede tærskler. De nuværende SSH-indstillinger skal være bagudkompatible.
- Udvid journalindsamlingen med kernel-felter og korrekt afgrænsning uden at
  udslette SSH-cursoren eller hælde alle kernelposter ind som SSH-hændelser.
- Opret separat firewallhistorik og netværksevidens i en testet migration;
  ingen firewallposter i SSH-loginoversigten eller SSH-ML-features.
- Gem fund atomisk med hændelser/cursor, deduplikér og gruppér gentagne fund.
  Historisk indlæsning må ikke give en strøm af gamle Discord-alarmer.
- Tilpas retention, `prune`, sikker backup/restore og datamængdegrænser til
  den ekstra logkilde, før den aktiveres i drift.
- Tilføj en netværksside og en kontrolleret Discord-beskedskabelon uden rå
  logs. Tidsvinduer, logniveau og begrænset dækning skal være synlige.
- Gennemfør read-only formatkontrol på Pi og derefter en begrænset prøve
  fra ejerens egen enhed. Trafik skal nå Pi'ens UFW-logsti; routerblokering
  eller Tailscale-regler, der stopper/omgår trafikken tidligere, giver ikke
  nødvendigvis et UFW-scanfund. Åbn ikke nye offentlige porte for testen.

## Synlighedsbegrænsninger

UFW `low` og `medium` ratebegrænser logningen. `medium` giver flere typer
logposter, men garanterer ikke fuld registrering af en hurtig scanning.
Tællinger skal derfor hedde registrerede pakker/logposter, ikke alle forsøg.
Ingen ekstra logning genskaber pakker, der aldrig nåede Pi'en.

Directed IPv4-broadcast afhænger af subnetkonfiguration; den rene detektor
kender endnu ikke lokale subnet. Det skal håndteres ved integrationens
sensor-/destinationsafgrænsning, ikke ved at antage at enhver adresse med
sidste oktet 255 er broadcast. Første kendte positive LAN-portscanning blev udført den 2. november 2026.
Af ti undersøgte porte blev 8 blokerede TCP SYN-logposter til fem unikke
testporte registreret i én gruppe og intet alert udløst ved tærskel 6.
Dette er en konkret detektionsbegrænsning for én test, ikke en påvist
fejl i detektorimplementeringen. Følsomhed, falske positiver og ydelse
er fortsat ikke målt på et større gennemgået netværksdatasæt.

## Kilder

- UFW-logniveauer og LOG_KERN:
  https://manpages.debian.org/trixie/ufw/ufw.8.en.html
- Journalens felter og `_TRANSPORT`:
  https://manpages.debian.org/trixie/systemd/systemd.journal-fields.7.en.html
- IANA protokolnumre (bl.a. 2/IGMP, 6/TCP og 17/UDP):
  https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

De eksterne kilder er gennemgået 1. november 2026. Tærskler og udviklingsrækkefølge
ovenfor er projektets designvalg; de er ikke leverandørgarantier.

## Praktisk afprøvning af tærskel

Efter første kendte Nmap-scan var 8 blokerede SYN-poster fordelt på
5 forskellige loggede porte. Der kom ingen alarm ved tærskel 6.
Ejeren har nu kontrolleret en *konfigurationsbaseret*, eksperimentel
ændring til tærskel **5**, stadig i 60 sekunder og med UFW `low`.
Detektionskoden er ikke ændret, og den første scan bliver ikke
genanalyseret retroaktivt. En ny afgrænset scan og efterfølgende
normaldrifts-observation er påkrævet før vurdering af følsomhed og
falske positiver. Fuld `-p-`-scanning er udskudt på grund af
mulig alarm- og journalbelastning.

## Afsluttet end-to-end-test

Den 2. november 2026 lykkedes en reel kontrolleret
Nmap-portscanning på Pi efter kalibrering til tærskel 5.
Et 60-minutters udtræk viste 5 unikke testporte i
60 sekunder, 1 TCP-scanningsalarm, 10 evidensposter,
1 Discord-outboxpost og ingen netværksanalysefejl.
Discord-status var `pending=0, delivered=2`, op fra
`delivered=1`, og et desktopnotifikationsbillede viste
portscanningsalarmen.

Dette beviser én end-to-end-funktionstest og cooldown-
gruppering, **ikke** fravær af falske positiver eller
garanteret detektion af alle scanninger. Den første
kendte scan ved tærskel 6 gav ingen alarm.

## Grafik til netværksdashboard (udviklingsbranch)

Der er nu en lille, privat grafsektion på `/network`, bygget med
**det eksisterende lokale Plotly**. API'et
`/api/network-charts` læser kun SQLite og returnerer aggregerede
observationer uden kilde-IP'er eller rå journalposter.

- **Blokerede TCP SYN-pakker over tid:** interval på 5 minutter ved
  1/6-timersvisning, 30 minutter ved 24 timer, 2 timer ved 7 dage og
  6 timer ved 30 dage. Kun intervaller med registrerede hændelser
  bliver plottet; en manglende søjle beviser ikke, at der var nul trafik.
- **Mest berørte porte:** højst **10** individuelt navngivne porte.
  Alle andre destinationporte summeres i **én** søjle med navnet
  `Øvrige porte`. Det er derfor aldrig en graf med 65.535 søjler.
- Der skelnes mellem pakker til en port og antal forskellige
  scannede porte. Graferne er kontekst og dokumentation;
  selve 60-sekundersdetektoren og dens alarmer beregnes uændret.
- Netværksgrafen er uafhængig af tabellens kilde-/protokolfiltre.
  Underliggende API kræver login og begrænser tidsinterval til
  højst 720 timer.

**Status:** Implementeret på `sprint-3/network-monitoring`,
men **ikke installeret på Yggdrasil Pi endnu**.
Den fungerende indsamling og Discord-alarm er uændret, indtil
der gennemføres en separat testet webopdatering.
