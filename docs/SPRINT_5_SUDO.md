# Sprint 5 – Sudo/administratoraktivitet: sikker datakilde og detektionsplan

**Status:** Read-only journalinventar og unit tests udviklet på GitHub. **Ikke installeret på Pi. Ingen sudo-detektor eller Discord-varsler aktive endnu.** Det er ikke en afsluttet Sprint 5-accept.

## Mål

Udvide Yggdrasil IDS med forklarlig overvågning af lokale administratorhandlinger: sudo-kommandoer, autentificeringsfejl og afviste sudo-forsøg. Vi registrerer **sikkerhedshændelser**, ikke automatisk ond hensigt. En sudo-kommando er ikke i sig selv en intrusion.

## Trin 1: bekæmp datagætteri med sikker, afgrænset live-audit

`deploy/sprint5_sudo_journal_audit.py` læser alene eksisterende journald via `journalctl --output=json`, som `yggdrasil-worker` allerede har autoriseret journaladgang til. Scriptet læser kun metadata fra `_COMM=sudo` og `_UID=0`; en forfalsket `SYSLOG_IDENTIFIER=sudo` er ikke nok. Det samler **kun antal**, fordelt på dag (UTC) og følgende grove kategorier:

| Kategori | Betydning |
| --- | --- |
| `command_invoked` | Sudo-invokation med registreret `COMMAND=...` |
| `pam_auth_failure` | PAM autentificeringsfejl for sudo |
| `incorrect_password` | Logmeddelelse om forkert sudo-adgangskode |
| `not_in_sudoers` | Afvist handling på grund af manglende sudo-rettigheder |
| `pam_session_opened` / `pam_session_closed` | PAM-session start/slut |
| `other_sudo` | Ukendt, men troværdigt sudo-format |

Der skrives **intet** til SQLite, sendes **ingen** Discord-besked og vises **ingen** brugeridentiteter, kommandoer, absolutte filstier eller journal-meddeleser. Audit sætter altid `production_sudo_detection_active=false`. Der er en øvre grænse på 50.000 journalposter. Den ændrer ikke UFW, SSH, Tailscale, systemd, sudoers eller sudo-konfiguration.

En nulmåling kan skyldes logformat, journalretention eller anden producentmetadata. Den beviser ikke, at sudo aldrig anvendes. Det skal vi vide, før vi påstår, at sensoren kan detektere bestemte hændelser.

## Trin 2: Regelbaseret analyse (afventer faktisk Pi-output)

Afgrænsede, konfigurerbare detektorer til **gentagne sudo-autentificeringsfejl** og **afvist sudo-brug** er de mest forklarlige startpunkter. Sudo-kommandoer med gyldige rettigheder registreres som normal administration og må ikke automatisk udløse medium/high-alarm. Cooldown og outbox skal følge den eksisterende grouping uden at sende en notifikation pr. PAM-session. Eventuel SQLite-migration skal bevare schema v4 og notifier-state, med frisk offline-backup og rollbackgate.

Parseren bør aldrig acceptere `SYSLOG_IDENTIFIER` alene som producentbevis og må ikke lagre hemmeligheder fra sudo `COMMAND=` argumenter. Før implementering fastslås, om `sudo` eller en anden journalproducent faktisk leverer disse felter på Debian 13.

## Trin 3: Acceptkriterier

1. CI med Ruff, pytest og wheel-build på Python 3.11/3.13.
2. Read-only Pi-inventar med hvilke journalmeddelelser der findes. **Ingen** rå logs uploades til GitHub.
3. Validerede tests af betroet producent, inputstørrelse, dubletter og korrekt behandling af hver dokumenteret meddelelsestype.
4. En afgrænset *autoriseret* sudo-test med klart forventet resultat og dokumenteret falsk-positiv-begrænsning; ingen `sudoers`-ændring nødvendig.
5. Hvis en live-service tilføjes: konsistent SQLite-backup, verificeret systemd-opstart, bevaring af SSH/UFW-detektorer og Discord-outbox, separat cooldown og privat dashboard-visning.

## Første Pi-kommando (kør først efter grøn CI og pinning af SHA)

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  git fetch --no-tags origin sprint-5/sudo-monitoring
  sha='INDSAET_CI_BESTAAET_FULD_SHA'
  test "$(git rev-parse origin/sprint-5/sudo-monitoring)" = "$sha"
  git show "$sha:deploy/sprint5_sudo_journal_audit.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python - \
      --since '2026-10-22 00:00:00'
)
```

**Sikkerhedsnote:** Kør kun som den eksisterende `yggdrasil-worker`, ikke som root. Outputtet må deles, fordi det kun indeholder aggregerede antal. Originale journald-data og sudo-kommandolinjer må forblive på Pi'en.

## Afgrænsning i eksamensopgaven

Sprint 4's Isolation Forest er kun trænet på syntetiske **SSH**-scenarier. En fremtidig sudo-detektor kan ikke kaldes ML-baseret, medmindre vi implementerer nye sudo-features og har repræsentativt, adskilt trænings- og testgrundlag. Sudo-alarmer skal derfor først være **regelbaserede**, med tydelig evidens.

## Faktisk Pi-audit: nul fund fra det snævre filter, 2. november 2026

Brugeren kørte `deploy/sprint5_sudo_journal_audit.py` fra fast Git-commit
`c35f086326142d39aeb3b041f3b62632fc5dc522` på Yggdrasil, som
`yggdrasil-worker`, fra `2026-10-22 00:00:00`. Output:
`rows_seen=0`, `trusted_sudo_rows=0`, nul i alle syv kategorier,
`production_sudo_detection_active=false`. Kommandoen afsluttede uden fejl.

**Fortolkning:** Dette viser kun, at den snævre journald-forespørgsel
med **begge** felter `_COMM=sudo` og `_UID=0` ikke fandt poster i den
valgte periode, under denne læserkonto og journaladgang. Det beviser
hverken fravær af sudo-brug, utilstrækkelige loggerettigheder eller
hvilken metadata-kombination Debian faktisk benytter.

### Næste datakildegate: aggregeret metadata-diagnostik

`deploy/sprint5_sudo_journal_metadata_diagnostic.py` undersøger alene:

1. Om mindst én systemjournalpost siden startdatoen er synlig
   med `journalctl --system --lines=1`.
2. Hvor mange poster der matcher kernelregistreret `_COMM=sudo`
   **uden** at kræve `_UID=0`, samt grove UID-, `_EXE`- og
   transportkategorier.
3. Hvor mange poster der blot har `SYSLOG_IDENTIFIER=sudo`, og hvor
   mange af disse faktisk har `_COMM=sudo` og root-UID.

`SYSLOG_IDENTIFIER=sudo` bruges **kun til discovery**, ikke som
autentisk bevis på en sudo-handling; tagget kan forfalskes af
ikke-privilegerede afsendere. Et processnavn alene beviser heller
ikke korrekt privilegeret oprindelse. Felter såsom `MESSAGE`,
`COMMAND=`, `_CMDLINE`, brugernavne, IP'er, konkrete
procesnavne, PID'er, UID'er fra enkeltposter og journalcursors
udskrives aldrig. Der er et loft på 10.000 journalposter pr.
afgrænset søgning; ved overskridelse stoppes analysen.

Dette er *kun* diagnostik og ikke en sudo-detektor. Ingen
serviceændringer, sudoers, SQLite, UFW eller Discord-ændringer.

**Pi-kørsel:** Brug kun fuld SHA fra grøn GitHub CI på branchen
`sprint-5/sudo-monitoring`; hent scriptet som kilde via
`git show SHA:deploy/sprint5_sudo_journal_metadata_diagnostic.py`
og udfør det som `yggdrasil-worker`. Analyser de aggregerede
resultater, før nogen produktionsdetektor designes.

## Pi-fund: sudo-kilden findes, men root-UID-filteret var forkert (2. november 2026)

Den første audit på Yggdrasil fandt 0 rækker med det fælles filter
`_COMM=sudo AND _UID=0`. Den efterfølgende read-only metadataaudit
(commit `c8f62f55bf38c2c155b605318a86ef758a435474`) viste
**101 rækker** med `_COMM=sudo` og ikke-root UID og
**109 rækker** med `SYSLOG_IDENTIFIER=sudo`. Alle 109 tag-matchede
rækker havde `_EXE=/usr/bin/sudo`, otte med root-UID og et andet
`_COMM`. Systemjournalen var tilgængelig.

**Kildekonklusion:** Sudo logges; den første nulmåling skyldtes
et for restriktivt filter. 109 rækker betyder ikke 109 sudo-kommandoer,
endsige angreb. Kildeidentifikation via et sudo-tag alene er ikke sikker.

En ny, selvstændig **read-only** audit,
`deploy/sprint5_sudo_trusted_exe_audit.py`, anvender i stedet
journalds betroede `_EXE=/usr/bin/sudo` uden at kræve root-UID eller
`_COMM=sudo`. Den tæller kategorierne for command, auth failure,
incorrect password, not-in-sudoers, PAM-session og ukendte formater,
men udskriver aldrig rå journalposter, brugere, kommandoer eller stier.
Den må kun udføres efter grøn CI med en pinnet commit af
`yggdrasil-worker`. Ingen produktionsdetektor installeres,
ingen ML-model trænes, og SQLite, systemd, SSH, sudoers, UFW og
Discord forbliver uændrede.

**Næste gate:** Se de faktiske aggregerede kategorier på Pi,
derefter beslut hvilke konkrete sudo-formater det er meningsfuldt
at lave regler for. Ret ikke produktionskonfigurationen på
baggrund af metadataoptællingen alene.

## Pi-accept af sudo-logformater, 2. november 2026

Den skrivebeskyttede audit `deploy/sprint5_sudo_trusted_exe_audit.py`
blev kørt af `yggdrasil-worker` på Yggdrasil fra commit
`be86915ceef24ef8280f69850642b3b84a7556a9`.
Den læste journalen siden `2026-10-22 00:00:00` og rapporterede:

| Troværdige sudo-logmeddelelser | Antal |
| --- | ---: |
| `command_invoked` | 34 |
| `pam_session_opened` | 38 |
| `pam_session_closed` | 37 |
| `pam_auth_failure` | 0 |
| `incorrect_password` | 0 |
| `not_in_sudoers` | 0 |
| `other_sudo` | 0 |
| **Samlet** | **109** |

Der var 60 poster den 24/10, 41 den 28/10, 4 den 31/10 og 4 den
01/11 (UTC). Det er **loglinjer**, ikke unikke kommandoer, sessioner,
angreb eller autorisationsskift. Én åbnet PAM-session mere end lukket
er ikke i sig selv dokumentation for et vedvarende login.
Der er ingen registrerede fejl i de genkendte meddelelsesformater,
men dette udelukker ikke, at andre logformater eller manglende
logdata skjuler hændelser. En enkelt realdata-audit kan heller
ikke validere den fremtidige detektors følsomhed.

### Sprint 5 – isoleret regelmotor, ikke installeret

For at evaluere et forsigtigt alarmdesign uden at ændre live-IDS'en
implementeres en **separat offline-prototype** i
`src/yggdrasil_ids/sudo_rules.py` og et rent read-only
journal-preview i `deploy/sprint5_sudo_rule_preview.py`.

- Accepter kun journalposter, hvor det betroede metadatafelt
  `_EXE=/usr/bin/sudo` er til stede. Afvis beskadigede
  tidsstempler, procesidentiteter, boot-ID'er og journalcursors.
- Genkend almindelige sudo-kommandoer og PAM-sessioner som
  **ikke-alarmgivende**. Genkend kun kendte, strengere
  logmønstre for fejl/afvisning; fritekst i `COMMAND=` må ikke
  kunne efterligne en sikkerhedsfejl.
- Prototypens fejlregel: mindst **3 særskilte sudo-PID'er** med
  et autentificeringsfejlsignal for samme journal-UID og boot
  i et rullende vindue på **300 sekunder**. Det er en konservativ
  proxy for gentagne sudo-processer, ikke en nøjagtig optælling
  af forkerte adgangskoder.
- Prototypens afvisningsregel: `not_in_sudoers` giver ét
  `sudo.permission_denied`-kandidatfund. En afvisning er
  ikke bevis på ondsindet aktivitet.
- Begge regler har **300 sekunders cooldown** pr. kildegruppe
  og regel. Dubletter med samme journalcursor tælles ikke igen;
  en PAM-fejl og en fejloversigt fra samme PID tæller højst
  som én proces i fejlreglen.
- Prototypen må kun udskrive kategorier, grænser og
  aggregeret antal kandidatfund. Ingen brugernavne,
  kommandoargumenter, rå meddelelser, PID/UID eller
  journalcursors offentliggøres.

Alle nye regler og logmønstre unit-testes med konstruerede
normale, mislykkede og afviste sudo-hændelser. Før vi har
kontrollerede, autentiske fejl-eksempler på Pi, kan vi
**ikke** sige, at den vil genkende alle Debian 13 sudo-fejl.
Vi må heller ikke fortolke 0 kandidatfund på den eksisterende
normale journal som en valideret falsk-positiv-rate.

**Status:** Ingen sudo-regler er koblet til live-collector,
SQLite-alerts, dashboard eller Discord. Ingen SSH-/ML-model er
ændret; ingen privilegier, sudoers, UFW eller systemd-tjenester
ændres. Enhver senere produktionsintegration kræver en særskilt
backup, rollout og rollback og en dokumenteret live-test.

## Afgrænset sudo-afvisningsforsøg – 2. november 2026 (ikke godkendt detektionsaccept)

Brugeren kørte på Yggdrasil en enkelt, kontrolleret,
ikke-interaktiv sudo-kommando som den begrænsede systemkonto
`yggdrasil-web`: `/usr/bin/sudo -n /usr/bin/true`.
Den ydre test af brugeridentiteten var bestået. Det indre
sudo-kald returnerede **exit-kode 1**. Standardfejl og
standardoutput blev sendt til `/dev/null`, så **den præcise
afvisningsårsag er ukendt**. Der blev hverken givet password,
ændret sudoers eller udført en privilegeret handling.

Efterfølgende blev `deploy/sprint5_sudo_rule_preview.py`
fra commit `b2a176a6c5f34e482f32f9a73d51398f42bac3cf`
kørt skrivebeskyttet som `yggdrasil-worker` med starttidspunkt
sat til to minutter før testen. Resultatet var
`journal_rows_seen=0`, `parsed_sudo_rows=0`,
`sudo.permission_denied=0` og
`sudo.repeated_auth_failure=0`.

**Dette er ikke dokumentation for, at sudo-afvisningsreglen
klassificerede forkert.** Der fandtes slet ingen rækker i
denne forespørgsel at klassificere. Uklarheden ligger
først i logdækning, journalfilter, tidspunkt eller
den ukendte exit-årsag; intet må konkluderes om
produktionsdetektionskvalitet, før hændelsen er lokaliseret.

**Næste gate:** Sammenlign aggregerede antal fra
`_COMM=sudo` og `SYSLOG_IDENTIFIER=sudo` med
`_EXE=/usr/bin/sudo` over en længere, præcist
angivet periode på Yggdrasil. Del ikke sudo-stderr,
rå loglinjer eller identiteter offentligt.
Undgå gentagne afvisningsforsøg indtil logdækningen
er afklaret. Scriptet til meta-diagnostik er allerede
tilgængeligt som `deploy/sprint5_sudo_journal_metadata_diagnostic.py`.
Ingen sudo-funktion er koblet på live IDS eller Discord.

### Opfølgning: ingen sudo-journalposter hele 2. november

På Yggdrasil kl. **2026-11-02T22:41:31+01:00** blev den
skrivebeskyttede `sprint5_sudo_journal_metadata_diagnostic.py`
kørt på hele perioden fra `2026-11-02 00:00:00`. Resultatet:
`recent_system_entry_visible=true`, men
`comm_sudo_query.rows=0` og `tag_sudo_query.rows=0`.

Der er dermed ingen matchende sudo-poster **for den dag under
`yggdrasil-worker`s journalvisning**, selv om tidligere sudo-poster
fandtes til og med 1. november. Den foregående kontrollerede
`sudo -n`-test gav exit-kode 1, men dens stderr var undertrykt:
hverken en præcis afvisningsgrund eller et verificeret
`not_in_sudoers`-journalformat kan udledes.

**Åbent problem:** Sammenlign, om root og collector-brugeren
ser samme journald-poster; kontrollér om `rsyslog`
eventuelt anvendes, og om en traditionel
`/var/log/auth.log` eller `/var/log/sudo.log` findes.
Udskriv kun antal og filmetadata – ikke faktiske loglinjer,
kommandoargumenter eller brugernavne. Foretag ingen nye
fejlede sudo-forsøg, før logdækningen er afklaret.

### Kontrol af journaladgang og alternative logfiler, 2. november 2026

En yderligere skrivebeskyttet kontrol viste **0 sudo-poster hos både
root og `yggdrasil-worker`** siden `2026-11-02 00:00:00`, både med
`_EXE=/usr/bin/sudo` og `SYSLOG_IDENTIFIER=sudo`.
`systemd-journald` var aktiv, `rsyslog` inaktiv, og
`/var/log/auth.log`, `/var/log/sudo.log` samt
`/var/log/syslog` fandtes ikke.

Dette udelukker en ren forskel i journal-læserettigheder for de
undersøgte metadatafiltre; det viser **ikke**, at sudo slet ikke
logger i en anden kanal. Årsagen til exit-kode 1 fra den
tidligere ikke-interaktive sudo-test er stadig ukendt, fordi
stderr var undertrykt. Ingen autorisation eller logningsopsætning
blev ændret.

**Næste afgrænsede kontrol:** Undersøg kun metadata for
`/dev/log`, journalds Unix-sockets og aktiv sudo-logpolicy.
Ingen flere afviste sudo-forsøg, og ingen ændring af sudoers,
journald, SSH eller IDS før en forklaring er påvist.

### Journald-syslog-sockets og daglig trafik – 2. november 2026

På Yggdrasil blev `/dev/log`, `/run/systemd/journal/dev-log` og
`/run/systemd/journal/socket` alle verificeret som eksisterende
Unix-sockets. Både `systemd-journald.socket` og
`systemd-journald-dev-log.socket` var aktive.

Den skrivebeskyttede journaloptælling med
`_TRANSPORT=syslog` viste **381 poster den 1. november**
og **320 poster den 2. november**.

**Fortolkning:** Journald modtager syslog-trafik på begge datoer;
en generel fejl i journalds syslog-socket er derfor ikke en
tilstrækkelig forklaring. Sudo-kildens faktiske logpolicy og
meddelelsesrute er stadig ikke verificeret. Antallet af
syslog-poster er ikke antal sudo-handlinger. Da stderr fra
den tidligere `sudo -n`-test blev undertrykt, er afvisningens
årsag heller ikke fastslået.

**Næste gate:** Inspicér kun sudo-version, logningsrelaterede
politiknøgler og eventuelle logdestinationer med sanitiseret
output. Ingen sudoers-ændringer, genstart, yderligere fejlede
sudo-forsøg eller ændring af IDS-produktion før logdækningen
er forklaret.

### Sudo 1.9.16p2 og syslog-facility 4/10 – næste afgrænsning

På Yggdrasil er `sudo` version **1.9.16p2**.
`sudo -V` viser den **kompilerede** syslog-facility
`authpriv`, samt succes-prioritet `notice` og
afvisnings-prioritet `alert`, *hvis syslog anvendes*.
Det alene dokumenterer ikke de aktuelt aktive
sudoers-Defaults eller individuelle brugerregler.

Aggregater fra journald med `_TRANSPORT=syslog`:

| Dato | `SYSLOG_FACILITY=10` (authpriv) | `SYSLOG_FACILITY=4` (auth) | Øvrige |
| --- | ---: | ---: | ---: |
| 2026-11-01 | 91 | 43 | 247 |
| 2026-11-02 | 73 | 18 | 244 |

Der findes altså auth-/authpriv-logposter den 2. november,
men ingen matchende sudo-poster i de tidligere undersøgelser.
**Årsagen er stadig ukendt.** Næste skridt er en
skrivebeskyttet, sanitiseret gennemgang af eventuelle
sudoers-logningsoverrides, uden at offentliggøre
rå sudoers-linjer eller ændre policy.
