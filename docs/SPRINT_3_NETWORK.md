# Sprint 3 · Firewallhændelser og mulig TCP-portscanning

## Status og grænser for denne leverance

**Udviklingsbranch:** `sprint-3/network-monitoring`, startet fra Sprint 2-merge
`63ea44a5363403b6da0725a894e48ea9a40a8bd7`.

**Første del:** isoleret UFW-parser og ren detektionsfunktion med tests.
**Anden del:** opt-in UFW-logindsamling til separat SQLite-tabel i skema v4,
med migration, transaktionel cursor, dubletkontrol, retention og backup.
**Ikke tilkoblet endnu:** TCP-scanningsreglen som live alarm, dashboard eller
Discord. Denne udviklingsversion er ikke accepteret på Pi; den skal ikke
installeres i drift, før kontrolleret migration og kildetest er planlagt.
`main` ændres ikke.

Der ændres ingen UFW-regler eller logniveauer. UFW forbliver på `low` under
udviklingen. En eventuel senere prøve med `medium` kræver en bevidst handling
på målmaskinen; dette bliver ikke udført af IDS-koden.

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
`preauth_disconnects` og Discord-outbox. TCP-scanningsdetektoren
**kører endnu ikke** i live collector; en firewallpost giver derfor ingen ny
Discord-besked eller alarm i dette trin.

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

**Driftssikkerhed:** Den kommende driftsaktivering kræver en verificeret
backup af SQLite v3, test af migration på backupkopi, diskbudgetkontrol,
måling af kernel-journalstrøm og en rollbackplan. Ingen ændring af UFW's
logniveau eller firewallregler er nødvendig for denne implementeringsdel.

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

## Næste implementeringsdel og acceptkrav

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
sidste oktet 255 er broadcast. Følsomhed, falske positiver og ydelse er endnu
ikke målt på et gennemgået netværksdatasæt.

## Kilder

- UFW-logniveauer og LOG_KERN:
  https://manpages.debian.org/trixie/ufw/ufw.8.en.html
- Journalens felter og `_TRANSPORT`:
  https://manpages.debian.org/trixie/systemd/systemd.journal-fields.7.en.html
- IANA protokolnumre (bl.a. 2/IGMP, 6/TCP og 17/UDP):
  https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

De eksterne kilder er gennemgået 1. november 2026. Tærskler og udviklingsrækkefølge
ovenfor er projektets designvalg; de er ikke leverandørgarantier.
