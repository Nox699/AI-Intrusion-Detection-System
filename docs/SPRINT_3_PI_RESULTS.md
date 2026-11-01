# Sprint 3 · Første Pi-acceptresultater

**Dato:** 1. november 2026 (Europe/Copenhagen)  
**Mål:** Yggdrasil (Raspberry Pi), eksisterende Sprint 2-drift  
**Testkilde:** `9b17bdac2af0db6f6af93eca574efee0b44a3b1e` på `sprint-3/network-monitoring`  
**Status:** **Bestået for migration på databasekopi og én kort logvolumenmåling.**
Ingen Sprint 3-installation, ændring af produktionsdatabase eller aktivering af
netværksindsamling er gennemført.

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
