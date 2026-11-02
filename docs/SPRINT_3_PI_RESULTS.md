# Sprint 3 · Første Pi-acceptresultater

**Dato:** 1. november 2026 (Europe/Copenhagen)  
**Mål:** Yggdrasil (Raspberry Pi), eksisterende Sprint 2-drift  
**Testkilde:** `9b17bdac2af0db6f6af93eca574efee0b44a3b1e` på `sprint-3/network-monitoring`  
**Aktuel status pr. 2. november 2026:** Sprint 3 installeret, schema v4, UFW-opt-in aktivt og **første TCP-portscanningsalarm leveret i Discord**. Tidligere statusafsnit nedenfor er kronologiske testnotater.

Dette er en referat af ejerens terminaloutput fra de afgrænsede kontroller.
Kun aggregerede antal offentliggøres, ingen adresser, journalindhold,
Discord-tokens, hemmelige stier med tokens eller private hændelses-ID'er.

## SQLite-v3-backup migreret på midlertidig kopi

Den installerede Sprint 2-CLI tog en konsistent backup, som blev kopieret til
et privat midlertidigt arbejdsområde. Kun kopien blev åbnet med
Sprint 3's `Repository.initialize()`. Arbejdsområdet blev slettet af
shellens `trap`, mens den root-beskyttede backup blev bevaret separat under
`/var/backups/yggdrasil-ids` (backupfilnavn er ikke offentliggjort).

| Kontrol | Før | Efter | Resultat |
| --- | ---: | ---: | --- |
| `PRAGMA user_version` | 3 | 4 | PASS (kun kopi) |
| `PRAGMA integrity_check` | ok | ok | PASS |
| `records` | 63 | 63 | PASS |
| `events` | 11 | 11 | PASS |
| `observations` | 11 | 11 | PASS |
| `alerts` | 2 | 2 | PASS |
| `discord_outbox` | 1 | 1 | PASS |
| `discord_outbox_meta` | 1 | 1 | PASS |
| `state` | 10 | 10 | PASS |
| Discord-outbox-instans | uændret | uændret | PASS (værdi ikke vist) |
| `firewall_events` | findes ikke | 0 | PASS |
| `network_evidence` | findes ikke | 0 | PASS |

Bekræftet terminaltekst: `PASS: Migration v3 -> v4 på databasekopi`,
`PASS: SQLite integrity_check`, `PASS: Eksisterende data og
Discord-identitet bevaret`, `PASS: Nye firewalltabeller er tomme`.
Der er **ikke** foretaget en opgradering af driftsdatabasen.

## Første kernel-journaloptælling

Kommandoerne blev kørt som `yggdrasil-worker` med systemjournalens
`_TRANSPORT=kernel` og `--since "5 minutes ago"`; UFW-tællingen
anvendte `--grep '\[UFW '`. Kun antallet af poster blev vist.

| Måling, seneste fem minutter | Resultat |
| --- | ---: |
| Kernelposter | 15 |
| UFW-poster | 15 |
| Andel af målte kernelposter, der var UFW | 100 % |
| Omtrentlig loghastighed i dette vindue | 3 poster/minut |

Denne **ene** måling tyder ikke på høj kernel-logmængde ved det observerede
tidspunkt. Den er ikke en spidsbelastningstest, og UFW `low` kan ratebegrænse
logs, så antal poster ikke kan fortolkes som antal faktiske pakkeforsøg.

## Uafsluttede kriterier

- Kontroller faktisk installeret pakke/kilde, systemd-tilstand,
  diskplads, backuprettigheder og lagringsbudget inden opgradering.
- Forbered en verificeret, **frisk** backup efter kontrolleret tjenestestop,
  gem tidligere wheel/kilde og dokumentér, hvordan v3 kan gendannes.
- Installer først Sprint 3 med `network.enabled=false` og verificér
  SSH, dashboard, notifier, databasen og driftslogning.
- Aktivér først bagefter `network.enabled=true` i et adskilt trin, med
  afgrænset måling fra ejerens egen enhed. Ingen offentlige porte åbnes.
- Udfør langtidstest, fuld genstart, negative fejltests og
  realistiske belastningsmålinger før fuld accept.

Tilbageførsel til den tidligere kode efter en v4-migration kræver den
gemte **v3-backup**, ikke blot reinstallering af den gamle wheel. En
tilbageførsel kan medføre tab af hændelser siden backuptidspunktet.
Se [opgraderingsplanen](SPRINT_3_PI_DEPLOY.md).

## Read-only installationskontrol, efter den første kopitest

Ejeren kørte en separat read-only preflight fra `vidar`-terminalen.
Følgende er observeret, uden at dele selve konfigurationsfilen:

| Kontrol | Observeret |
| --- | --- |
| `yggdrasil-collector.service` | active |
| `yggdrasil-web.service` | active |
| `yggdrasil-notifier.service` | active |
| NVMe-filsystem | ca. 1,8 TB i alt; 22 GB brugt; 1,7 TB ledigt (2 % brugt) |
| `/var/lib/yggdrasil-ids` | 200 KB |
| `/var/backups/yggdrasil-ids` | 1,2 MB |
| Python | 3.13.5 |
| Installeret pakkes versionsnummer | `yggdrasil-ids 0.1.0` |
| Produktionsdatabaseskema | 3 |
| SQLite `quick_check` | ok |
| `app.mode` | live |
| `network.enabled` | false |
| Lokalt Git-checkout | `658c9140f8b224ae3ab21b4d161f44c3e91697c9` |
| `git status --short` | Intet output (rent arbejdsområde) |

**Vigtigt:** Lokalt Git-HEAD og pakkens versionsnummer beviser ikke, hvilken
kildecommit der faktisk er installeret i `/opt/yggdrasil-ids/venv`.
Den tidligere installerede `venv` skal derfor bevares i en root-beskyttet,
separat arkivfil før opdatering, så rollback ikke bygger på en antagelse.
En ny backup af v3-databasen skal desuden tages **efter tjenestestop**
før selve migrationsskridtet. Read-only preflight er bestået; selve
opgraderingen og nettets observerbarhed er stadig uprøvet.

## Releaseforberedelse udført på Pi (før driftsinstallation)

Ejeren gennemførte `deploy/sprint3_prepare.sh` fra commit
`07fab99c88fe51a2cc455f51788bb17fd6c37fa4`.
Før opbygning blev SQLite schema v3 og deaktiveret netværksindsamling verificeret.
Den nye wheel blev bygget og verificeret; et arkiv af det eksisterende
installerede Python-miljø blev gemt i en root-beskyttet mappe.

- Wheel: `yggdrasil_ids-0.1.0-py3-none-any.whl`
- SHA-256 for wheel: `859726739016d0876e14a31d4762c203062f6a5530ad6da3013ad6df8da72b5e`
- SHA-256 for tidligere venv: `fb38bc7b05024d6f52873fd3ec85093e157b2b4a7e607e0b70a88690a994faeb`
- Forberedt release-mappe: `/var/backups/yggdrasil-ids/sprint3-prepared-07fab99c88fe51a2cc455f51788bb17fd6c37fa4`
- Samlet størrelse: `89M`

Den rapporterede slutttekst var `PASS: Forberedelse færdig; intet er installeret eller genstartet.`
Dette er **ikke** en installation på Pi. Produktionsmigrering og live scan-test afventer.
To fejlede sudo-adgangskodeforsøg blev fulgt af vellykket autentificering.
Der er ingen observerede ændringer i IDS-tjenester eller adgangsregler.

## Første produktionsopgraderingsforsøg: afbrudt

Ejerens terminaloutput dokumenterer følgende sekvens:

1. V3 database og `network.enabled=false` kontrolleret; notifier-checkpoint OK.
2. Forberedt wheel og tidligere `venv` verifieret med SHA-256.
3. De tre IDS-tjenester stoppet.
4. Frisk offline-v3-backup oprettet med `integrity_check=ok`.
5. Data, Discord-state, konfiguration og systemd-units arkiveret privat.
6. Sprint 3-wheel installeret og root-import af schema v4 og netværksregel bestået.
7. **STOP:** CLI gav `ModuleNotFoundError: No module named 'yggdrasil_ids.cli'`
   ved første forsøg på `yggdrasil-ids init` som `yggdrasil-worker`.

Fejlfase: `migrating-db`. Den automatisk efterfølgende genstart blev
derfor **ikke** kørt. Den faktiske aktuelle databaseskema- og
tjenestestatus skal efterprøves på Pi, før flere skrivehandlinger udføres.
Den efterfølgende read-only diagnose **bekræftede filrettighedsfejlen**:
`yggdrasil_ids/cli.py` fandtes i wheel-arkivet, men den installerede
`yggdrasil_ids`-mappes rettigheder var `0700`, og `cli.py` havde
`0600`. Import af `yggdrasil_ids.cli` som `yggdrasil-worker` fejlede.
Databasen var stadig schema v3 med `quick_check=ok`. Tjenesterne viste:
collector `failed`, web `inactive`, notifier `inactive`.

**Reparation bekræftet på Pi:** Kun programkodens pakkemappe fik
mapperettigheder `0755` og filrettigheder `0644` (ikke secrets eller
database). Derefter lykkedes import af `yggdrasil_ids.cli.main` samt
`SCHEMA_VERSION == 4` som alle tre servicekonti:
`yggdrasil-worker`, `yggdrasil-web` og `yggdrasil-notifier`.
Terminalen afsluttede med
`PASS: Python-pakkens rettigheder er repareret`.

**Status efter reparationen:** Sprint 3-koden kan importeres, men der er endnu
ikke vist en v4-produktionsmigration eller genstartede IDS-tjenester.
Derfor må den fulde driftsopgradering ikke markeres som bestået endnu.

En senere rettelse af scriptet må ikke markeres som en bestået
produktionsaccept, før Pi'ens faktiske import, schema, servicekonti,
journal og dashboard er testet efter genstart.

## Produktionsmigration og genstart efter rettighedsreparation: bestået

Ejeren gennemførte `deploy/sprint3_resume_after_permissions.sh` og
rapporterede følgende uafhængige kontroller som `PASS`:

| Kontrol | Observeret resultat |
| --- | --- |
| `yggdrasil-worker`, `yggdrasil-web`, `yggdrasil-notifier` | Kan alle importere Sprint 3 |
| Frisk v3-backup og drift før migration | Samme data, SQLite-integritet OK |
| Discord-notifier checkpoint og outbox | Konsistente før migration |
| Produktionsmigration v3 til v4 | Bestået |
| SQLite-integritet og eksisterende SSH-/Discord-historik | Bevaret |
| Collector doctor og journaladgang | Bestået |
| Collector-service | Aktiv |
| Web doctor | Bestået |
| Lokalt dashboard-login | HTTP 200 |
| Discord notifier efter genstart | `pending=0`, `delivered=1` |
| Alle tre IDS-tjenester | Aktive og kontrolleret |
| `network.enabled` | Stadig `false` |

Eksisterende rollback-backups blev bevaret i den private mappe
`/var/backups/yggdrasil-ids/sprint3-offline-Ga0vDrfK`.
SSH, UFW og Tailscale blev ikke ændret.

**Fortolkning:** Den installerede Sprint 3-kode og produktionsskema v4
er nu praktisk verificeret; dette er **ikke** en accept af live
firewallindsamling, en dokumenteret TCP-scanningsalarm, 24-timers
stabilitet eller målt falsk-positiv-rate. De kræver særskilte prøver.

## First live UFW opt-in succeeded

Owner executed the pinned first opt-in at
957c65c7d0a39f560eac04bc71e4f2dd8affb587.
SQLite schema v4 and a fresh v4 backup passed integrity checks.
The separate network section was enabled without other configuration changes.
Collector, private dashboard (HTTP 200) and notifier all remained active.
UFW stayed on low, SSH and Tailscale were not changed.

Initial normalized firewall records: **1**. Scan alerts: **0**.
The private opt-in backup is stored under:
 /var/backups/yggdrasil-ids/sprint3-network-optin-WewUNOgt

This verifies journal ingestion for one event, **not** scan detection or
Discord delivery. See SPRINT_3_SCAN_ACCEPTANCE.md for the next bounded test.

## Første kontrollerede LAN-portscanning – Nmap-resultat

**Dato:** 2. november 2026 kl. 00:10 CET (Nmap-klientens tidsangivelse).  
**Klient:** Ejerens Ubuntu på laptop, Nmap 7.94SVN.  
**Destination:** Egen Raspberry Pi på privat LAN (IP udeladt af offentlig rapport).

Nmap TCP connect-test med `-sT -Pn -n --scan-delay 2s
--max-retries 0 --host-timeout 90s -p 45010-45019`:

- Alle **10/10** undersøgte TCP-porte rapporteret som `filtered`.
- Nmap rapporterede `Host is up`.
- Varighed: **22,28 sekunder**.
- Advarsel om, at nul retransmissioner var tilladt.
- Ingen åbne porte fundet i det afgrænsede interval.

**Vigtig adskillelse:** `filtered` angiver, at Nmap ikke fik
tilstrækkeligt svar til at fastslå porttilstand. Det er foreneligt
med blokering, men dokumenterer **ikke** i sig selv UFW-logning.
Endnu ingen SQLite-optælling efter testen, ingen verificeret
`network.tcp_port_scan`-alarm og ingen bekræftet Discord-levering.
Derfor er portscan-accepten **ikke bestået endnu**.

Næste skridt er read-only indsamling af aggregerede mål
fra `deploy/sprint3_network_observe.py`, og kontrol af notifierstatus
i sammenligning med baseline. UFW forbliver `low`.

## Pi-kontrol efter første scanning – positiv trafik, utilstrækkelig regel-evidens

Efter Nmap-testen blev den installerede databases UFW-/alarmhistorik
kontrolleret med den privatlivsbeskyttende read-only-helper
`deploy/sprint3_network_observe.py` fra kildecommit
`2f550430e31e6763cd783b05b98166710319299a`.

| Måling | 10 minutter | 60 minutter |
| --- | ---: | ---: |
| Firewallposter i vinduet | 16 | 62 |
| Blokerede TCP SYN i vinduet | 0 | 8 |
| Pakker til testportene 45010–45019 | 0 | 8 |
| Grupperede kilder/sensorer for testportene | 0 | 1 |
| Maks. forskellige testporte i 60 sekunder, samme gruppe | 0 | **5** |
| Netværksscanningsalarmer | 0 | 0 |
| Netværksevidens | 0 | 0 |
| Discord-outboxposter for denne detektor | 0 | 0 |

60-minuttersmålingen viste også **62 kumulative firewallhændelser**, nul
registrerings-/analysefejl og ingen dataqualitetsflag. Collector var
`running` og heartbeat var **0 sekunder gammel**.
Den tidligere 10-minuttersmåling viste **21 kumulative hændelser**
og heartbeat **3 sekunder gammel**, men ingen testportposter i netop dette
kortere tidsvindue; det er ikke bevis for, at scanningen ikke blev opsamlet.

Notifierens særskilte status efter 60-minutterskontrollen:
`pending=0`, `delivered=1`, `last_seq=1`,
`cooldown_seconds=0`. Dermed er der ikke evidens for en ny
Discord-scanningsnotifikation.

**Evaluering:** Testen er en kendt positiv scanning af 10 testporte
(Nmap), men kun 5 forskellige porte blev set som blokerede SYN inden
for regelens 60 sekunder. Den programmerede tærskel er 6, så **ingen
alarm er korrekt ud fra observerede regeldata**.
Målt end-to-end-detektion af denne scanning = **0/1**;
en enkelt test giver ikke en robust estimeret detektionsrate.
Dette er et observeret detektionsmiss i hele pipeline-kæden,
**ikke** dokumentation for fejl i selve detektorfunktionen.

Der er 8 loggede SYN-pakker fordelt over 5 forskellige destinationsporte;
det kan skyldes gentagne forsøg mod nogle porte og manglende logging af
andre. UFW `low` ratebegrænser logning, men fra disse aggregater alene
kan man **ikke bevise**, at ratebegrænsning var den konkrete årsag.
Før ny scanning måles fordeling pr. testport uden IP-oplysninger og
evt. logprefix for at skelne dæknings- og regelsvigt.
UFW `medium` er fortsat ratebegrænset, så en ren skift til medium
garanterer ikke, at alle ti porte logges.

## Detaljeret portfordeling fra første scan

En yderligere read-only forespørgsel mod SQLite, afgrænset til
testportene og det tilsvarende tidsrum, gav denne anonymiserede
portfordeling (ingen IP-adresser eller rå logs):

| Testport | TCP-poster | Blokerede SYN |
| --- | ---: | ---: |
| 45010 | 2 | 2 |
| 45011 | 0 | 0 |
| 45012 | 0 | 0 |
| 45013 | 1 | 1 |
| 45014 | 0 | 0 |
| 45015 | 2 | 2 |
| 45016 | 2 | 2 |
| 45017 | 0 | 0 |
| 45018 | 0 | 0 |
| 45019 | 1 | 1 |

**I alt:** 8 registrerede blokerede SYN til **5** forskellige porte.
Det bekræfter den tidligere 60-minutters aggregerede observation.
Registrering af samme port flere gange øger ikke antallet af unikke
porte. Manglende loglinjer er ikke i sig selv bevis for, hvilken mekanisme
der undertrykte dem.

## Planlagt grænseforsøg: 6 → 5

Ejeren bemærkede, at uventede portforsøg på eget LAN er interessante.
En **foreløbig konfigurationsændring** fra 6 til 5 forskellige,
blokerede TCP SYN-destinationsporte inden for 60 sekunder er derfor
foreslået og forberedt i `deploy/sprint3_tune_threshold5.sh`.
Dette er **ikke endnu aktiveret** på Pi.

Det er en ændring af følsomhed, ikke en fejlrettelse. Grænsen vælges
på baggrund af eget netværks risikoprofil og den observerede logdækning;
den må ikke efterfølgende påstås at være objektivt optimal. De gamle
8 logposter giver stadig **ingen retroaktiv alarm**. En ny kontrolleret
scan skal fungere som en separat test efter konfigurationsændringen.
Observer også normale LAN-perioder for mulige falske positiver
(fx netværksdiscovery, administration eller legitim software).
UFW-forbliver `low`, og pakken geninstalleres ikke.

Screenshot- og bilagsplan:
[SPRINT_3_SCREENSHOTS.md](SPRINT_3_SCREENSHOTS.md).

## Eksperimentel tærskel sænket til fem porte – praktisk Pi-resultat

Ejeren kørte `deploy/sprint3_tune_threshold5.sh` fra commit
`c1f6ec1be453de87449a5cf33a988a3537b685e4` og rapporterede:

- `PASS: Live schema v4 og eksisterende 6-port-konfiguration er verificeret`.
- `PASS: Kun distinct_ports_threshold ændret fra 6 til 5`.
- `PASS: Ny eksperimentel tærskel = 5 porte på 60 sekunder`.
- `PASS: Alle tre IDS-tjenester aktive; UFW low og netværksindsamling bevaret`.

Privat konfigurationsbackup:
`/var/backups/yggdrasil-ids/sprint3-threshold5-MkMb1mZK`.

Denne ændring påvirker **kun fremtidig analyse** efter genstart, ikke
historiske hændelser eller tidligere alarmer. Test 1 blev gennemført
med tærskel 6 og gav ingen alarm; det resultat bevares som faktisk
evidens. Den nye tærskel 5 er valgt efter at have set testresultatet
og er derfor **kalibrering**, ikke uafhængig validering. Vi mangler
en ny kontrolleret test, måling af Discord-levering og observation af
falske positiver under normal drift.

### Forventet alarmgruppering og hvorfor fuld scanning afventer

Den aktuelle kode grupperer `network.tcp_port_scan`-fund med samme
kilde, destination, interface, host, boot og namespace, hvis fund følger
hinanden inden for den eksisterende cooldown på 300 sekunder.
Opfølgende fund opdaterer et alarmforløb; en ny alarm indsætter én
Discord-outboxpost. En lang scanning, pauser længere end cooldown eller
flere sensor-/destinationsgrupper kan dog oprette flere alarmer.
Dette er **ikke** en ubetinget garanti mod mange notifikationer.
Scanning af 65.535 porte kan desuden øge journal- og databasebelastning
betydeligt. Før en fuld TCP-scan kræves en afgrænset ny test med
tærskel 5, kontrol af alarmgruppering og målt belastning.

## Anden Nmap-test efter tuning – analyse afventer

**Dato:** 2. november 2026 kl. 00:53 CET (klientens Nmap-output).  
**Miljø:** Samme private Pi og testporte 45010–45019 på eget LAN.  
**Konfiguration:** Eksperimentel `distinct_ports_threshold=5`,
`window_seconds=60`, UFW `low` og de tre IDS-services aktive
ifølge foregående konfigurationstest.

Den anden Nmap 7.94SVN-kørsel med
`-sT -Pn -n --scan-delay 2s --max-retries 0 --host-timeout 90s` viste:
- **10/10** testporte som `filtered`.
- Varighed: **22,21 sekunder**.
- Nmap angav `Host is up` og en advarsel om nul retransmissioner.

**Ingen SQLite-måling efter den anden scanning er endnu leveret.**
Derfor er det endnu uvist, om threshold 5 blev nået, om
`network.tcp_port_scan` gav en alarm, og om Discord fik en ny
besked. En `filtered`-port alene dokumenterer ikke en IDS-alarm.
Næste handling er samme read-only aggregerede kontrol med et
60-minutters vindue og notifierens leveringsstatus.

## Accepttest 2: detektion og Discord-levering bekræftet

**Nmap fra ejers Ubuntu-laptop:** 2. november 2026 kl. 00:53 CET.
Testen omfattede ti høje TCP-porte (45010–45019) mod egen private
Yggdrasil-server, alle meldt `filtered`, varighed **22,21 sek.**
IDS var allerede konfigureret med `distinct_ports_threshold=5`
inden for 60 sekunder; UFW-logniveau var fortsat `low`.

Read-only database- og notifierkontrol efter testen:

| Mål | Observeret |
| --- | ---: |
| Firewallposter i 60-minuttersvinduet | 129 |
| Blokerede TCP SYN i 60-minuttersvinduet | 31 |
| TCP-pakker på testportene i 60-minuttersvinduet | 14 |
| Kilde-/sensorgrupper på testportene | 1 |
| Maks. unikke testporte i et 60-sekundersvindue | **5** |
| `network.tcp_port_scan`-alarmer | **1** |
| Netværksevidensposter | **10** |
| Discord-outboxposter fra portscan-detektoren | **1** |
| Samlede akkumulerede firewallhændelser | 151 |
| Netværksanalysefejl | 0 |
| Netværksfejl-/datakvalitetsflag | begge `false` |
| Collector | `running`, heartbeat 2 s |
| Discord-notifier | `pending=0`, `delivered=2`, `last_seq=2` |

Tidligere notifierstatus var `delivered=1`, `last_seq=1`;
der blev således leveret **én ny** besked. Brugeren sendte et
Discord-desktopnotifikationsbillede med
**»Yggdrasil IDS — ny alarm«** og
**»Mulig TCP-portscanning (UFW)«**.

**Konklusion:** Kæden Nmap → UFW → journal/SQLite →
`network.tcp_port_scan` → 1 alarm / 10 evidensfund →
1 Discord-outboxpost → faktisk Discord-levering er
**bestået for denne afgrænsede test**. De ti fund blev
grupperet i ét alarmforløb og gav ikke ti Discord-beskeder.

**Databegrænsning:** En 60-minutters databaseopgørelse kan omfatte
både den første scanning kl. 00:10 og den anden kl. 00:53.
Derfor tilskrives de 129 firewallposter, 31 SYN og 14
testportpakker **ikke udelukkende** den anden scanning.
Den første scanning ved tærskel 6 gav **ingen alarm**.
Tærsklen 5 blev valgt efter denne baseline og er derfor
eksperimentel kalibrering, ikke uafhængig statistisk validering.
En falsk-positiv-rate, dækning ved langsomme scanninger og
langtidsbelastning er endnu ikke målt.

**Rapportbilag:** Discord-screenshot er modtaget i samtalen,
men er ikke overført til repo eller rapport.
Se `docs/SPRINT_3_SCREENSHOTS.md`.

## Graf-release installeret på Pi – 2. november 2026

**Source SHA:** `0cdcf4c3b6c62718f1ef4d5c5d35ee96362bd581` (CI bestået på Python 3.11 og 3.13).

**Staging:** `sprint3_charts_prepare.sh` bestod; schema v4, produktionsprofil
og kun godkendte graf-/dashboardfiler blev verificeret. Wheel på 100023 bytes
inkluderede grafassets. Ingen IDS-tjenester blev stoppet under staging.

- Wheel SHA-256: `56dbb6e369175a7a044c8752d675f024fc1db63ab25c37dd127f606a35ea0396`.
- Tidligere venv SHA-256: `9477576d552dfe916ccf5128f67e416b62b3ddf6ecdfb53753ffca8ea767c67b`.
- Privat stagingmappe: `/var/backups/yggdrasil-ids/sprint3-charts-prepared-0cdcf4c3b6c62718f1ef4d5c5d35ee96362bd581` (90 MB).

**Live-deploy:** `sprint3_charts_deploy.sh` bestod uden fejl.
Frisk offline schema-v4-backup er verificeret; ny wheel installeret.
Alle tre servicekonti kan importere CLI. `yggdrasil-web` kunne læse graf-
data og verificerede højst ti individuelle porte. Login-HTTP 200,
ikke-autentificeret `/api/network-charts` HTTP 401.
Discord checkpoint bevaret: `pending=0`, `delivered=2`.
Eksisterende SSH-, netværks-, alarm- og notifierhistorik bevaret.
Collector, web og notifier aktive efter genstart; UFW stadig `low`.

- Offline-backup: `/var/backups/yggdrasil-ids/sprint3-charts-offline-PS5JlXUx`.
- Rollback: `previous-venv.tar.gz` i ovenstående stagingmappe.

**Status:** Pi-installation og server-side kontroller **bestået**.
Faktisk browser-rendering af grafer og screenshot S3-J **afventer**.
Observation af normale perioder og falske positiver er ikke afsluttet.
Installationsscriptet skal **ikke** genkøres efter vellykket installation.

## Afgrænset observation efter grafopdatering (2. november 2026)

Ejeren kørte en **read-only** SQLite-optælling fra
**2. november kl. 01:15 CET** til tidspunktet for forespørgslen.
Resultat: **139 lagrede `firewall_events`**, men **0 nye
`network.tcp_port_scan`-alarmer** målt på `first_seen` i samme periode.

Resultatet bekræfter aktivitet i loghistorikken uden nye
scanalarmer i dette udsnit. Der er endnu **ikke** givet en
uafhængig klassifikation af alle 139 poster som normaltrafik;
målingen dokumenterer derfor **ikke** nul falske positiver eller
en bestemt falsk-positiv-rate. En eventuel anden scanner i perioden
er ikke udelukket på grundlag af de aggregerede tal alene.
Dashboardets faktiske browser-rendering og screenshot S3-J afventer.
