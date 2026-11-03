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

### Sudoers-konfigurationsaudit: ingen eksplicitte log-overrides

På Yggdrasil blev `/etc/sudoers` og seks eksisterende
ikke-skjulte filer i `/etc/sudoers.d` gennemgået uden at
udskrive filindhold. En simpel parser af `Defaults`-linjer
fandt **ingen eksplicitte** forekomster af `log_allowed`,
`log_denied`, `syslog`, `syslog_goodpri`,
`syslog_badpri`, `logfile` eller `log_servers`.

**Fortolkning:** Der er ikke konstateret et synligt,
tekstligt override blandt de syv undersøgte filer.
Denne kontrol er ikke en fuld fortolkning af effektiv
sudo-policy og dækker ikke nødvendigvis eventuelle
yderligere sudoers-kilder, inkluderede filer,
policy-plugins eller indstillinger filtreret af andre
regler. Logdækningen på Yggdrasil er fortsat **ikke**
accepteret, og den tidligere mislykkede `sudo -n`-test
må ikke tælle som en valideret alarmtest.

**Næste kontrol:** Aflæs kun metadata om `sudoers:`
i NSS, registrerede sudo-plugins og journalds effektive
logniveau/ratelimit; ingen konfigurationsændringer.

### Standard sudoers-plugin og journald uden eksplicitte overrides

Den skrivebeskyttede kontrol viste:

- `/etc/nsswitch.conf`: ingen særskilt `sudoers:`-kilde angivet.
- `/etc/sudo.conf`: **0 eksplicitte pluginlinjer**.
- `systemd-analyze cat-config systemd/journald.conf`: ingen
  aktive, eksplicitte værdier for `MaxLevelStore`,
  `RateLimitIntervalSec` eller `RateLimitBurst`.

**Vigtigt:** `0` eksplicitte sudo-plugins betyder ikke,
at der ikke findes et aktivt policy-/audit-plugin. Sudo
bruger som standard `sudoers` til policy, audit og
I/O-logning, når der ikke er særskilte pluginlinjer.
Ingen journal-overrides betyder heller ikke, at journalens
standardindstillinger er deaktiveret. Der er derfor
*ikke* påvist en fejl i hverken plugin- eller journald-config.

**Næste kontrol:** Læs de kompilerede sudo-logindstillinger
og sammenlign aggregerede sudo-relaterede syslog-poster på
begge datoer uden at vise beskeder eller identiteter.
Ingen ændring af sudoers eller aktive IDS-services.

### Tværgående journalaudit 1.–3. november 2026: sudo-hændelser mangler

En skrivebeskyttet gennemgang af **alle systemjournalposter**,
uden indledende `_COMM`, `_EXE`, `SYSLOG_IDENTIFIER` eller
transportfilter, gav følgende lokale kalenderdage
(`Europe/Copenhagen`):

| Lokal dato | Journalposter i alt | `_EXE=/usr/bin/sudo` | `_COMM=sudo` | `SYSLOG_IDENTIFIER=sudo` | `authpriv` | `_TRANSPORT=audit` | `MESSAGE` indeholder "sudo" |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2026-11-01 | 3.537 | 4 | 0 | 4 | 91 | 0 | 4 |
| 2026-11-02 | 3.345 | 0 | 0 | 0 | 73 | 0 | 0 |
| 2026-11-03 (delvis dag) | 170 | 0 | 0 | 0 | 2 | 0 | 0 |

Det er et **reelt, uafklaret datadækningsproblem** i den
tilgængelige systemjournal fra 2. november og frem. Et
gennemført, trivielt `sudo /usr/bin/true` blev også fulgt
af nul matchende journalposter på de tre sudo-metadatafelter.
Sudo 1.9.16p2 rapporterer `log_allowed`, `log_denied`,
`authpriv` og standard sudoers-policy-/audit-plugins som
tilgængelige; tidligere konfigurationsaudit viste ingen
eksplicitte overrides for de undersøgte logfelter.

**Vi har ikke påvist årsagen.** Dette kan ikke tilskrives
en fejl i vores parser: den ser slet ingen sudo-poster.
Næste sikre diagnostiske forsøg er én harmløs
`logger`-meddelelse til `/dev/log` på `authpriv.notice`
med unik testtag, og efterfølgende aggregeret journald-
verifikation. Det tester kun logtransporten, ikke sudo-
autorisering eller detektorens følsomhed. Ingen sudoers-,
systemd-, SSH- eller IDS-ændringer.

### Løst: `--system` udelukkede sudo fra brugerjournaler (3. november 2026)

En sikker, skrivebeskyttet sammenligning af journal-**scope**
fra 2. november, udført som root, viste:

| Journalvisning | Testtag | Testbesked | `_EXE=/usr/bin/sudo` | `SYSLOG_IDENTIFIER=sudo` |
| --- | ---: | ---: | ---: | ---: |
| Med `journalctl --system` | 0 | 0 | 0 | 0 |
| Uden `--system` (alle tilgængelige journaler) | 1 | 1 | **626** | **626** |

**Revideret konklusion:** Sudo og syslog har faktisk logget.
Alle tidligere påstande om, at sudo-logningen var ophørt
fra 2. november, var forhastede: vi læste den forkerte
journald-visning. Det er en konkret **kilde-/scope-fejl**
i alle Sprint 5-probes, der bruger `--system`.
Meddelelserne ser ud til at ligge i journaler uden for
systemjournalen; et separat tjek af journalens metadata
skal afgøre deres nøjagtige placering.

**Næste gate (ingen produktion):** Verificér, at den eksisterende
`yggdrasil-worker` også kan se disse sudo-poster **uden**
`--system`, og sammenlign root/worker på nøjagtigt samme
datointerval. Ellers kræves et bevidst adgangs- og
privatlivsdesign inden integration. Opdater derefter
kun Sprint 5's isolerede, skrivebeskyttede probes til
korrekt scope og tilføj unit-regressionstest. En ændring
af den aktive collector, systemd-tjenester eller sudoers
er **ikke** udført eller godkendt.

**Databegrænsning:** De 626 er journalposter, ikke unikke
sudo-kommandoer eller angreb. Den oprindelige sudo-test med
exit-kode 1 har fortsat ikke et verificeret label
eller en bekræftet detektorrespons.

### Journal-scope identificeret og rettet: 627 sudo-poster synlige for worker

**3. november 2026, read-only kontrol.** Den samme journalsøgning
med `_EXE=/usr/bin/sudo` blev sammenlignet som root og
`yggdrasil-worker` for perioden fra
`2026-11-02 00:00:00` til aktuel lokal tid:

| Scope | Root | yggdrasil-worker |
| --- | ---: | ---: |
| `journalctl --system` | 0 | 0 |
| `journalctl` uden `--system` | **627** | **627** |

En separat, bredere systemsøgning havde tidligere fundet
626 sudo-poster uden `--system` samt én `logger`-testbesked,
mens `--system` gav nul. Differencen 626 → 627 kan skyldes
yderligere aktivitet mellem målingerne; tallene er ikke
antal kommandoer, angreb eller særlige brugere.

**Konklusion:** Sudo-data er tilgængelige for den eksisterende
worker, men uden for systemjournalvisningen. Diagnosen om
ophørt sudo-logning fra 2. november var derfor forkert.
Årsagen var begrænset **journal-scope**, ikke dokumenteret
sudo-policy-, syslog-, socket- eller journalrettighedsfejl.
Det er endnu ikke dokumenteret præcis hvilken journalfil
posterne ligger i.

**Kodeændring i Sprint 5:** Den selvstændige, skrivebeskyttede
`deploy/sprint5_sudo_trusted_exe_audit.py` og dens delte
`read_journal` (benyttet af
`deploy/sprint5_sudo_rule_preview.py`) fjerner `--system`,
men beholder det journalsupplerede kildefilter
`_EXE=/usr/bin/sudo` og en grænse på 10.000 rækker.
Den skrivebeskyttede metadata-diagnose anvender også
alle tilgængelige journaler. Unit-regressionstests
kontrollerer, at `--system` ikke bliver genindført.

**Adskilt fra produktion:** Den eksisterende
`JournalCollector` for SSH og UFW bliver **ikke**
ændret til at læse alle brugerjournaler. Det ville
udvide både datamængde og privatlivseksponering uden
for den aftalte test. Sudo skal integreres som en
særskilt, begrænset kilde efter særskilte tests
og backup-/rollbackkontrol; ingen ny live-collector,
SQLite-migration eller Discord-alarm er aktiveret.

**Næste gate:** Kør den opdaterede offline-preview som
`yggdrasil-worker` fra en fuld, CI-godkendt commit
med `PYTHONPATH` fra en midlertidig checkout.
Del kun aggregeret JSON; lad rå sudo-journalmeddelelser
blive på Pi. Evaluer hvor mange af de 627 poster,
der kan parses, og om virkelige fejltyper genkendes.

### Pi-accept af korrigeret journalscope: 641 sudo-poster (3. november 2026)

På Yggdrasil blev den rene Sprint 5-gren fra commit
`7a46c935a505dcaeda70b35335ee8298e6e7293b` kørt
**read-only** som `yggdrasil-worker`, med
`PYTHONPATH` og kode udtrukket fra fast Git-SHA til en midlertidig mappe,
og `--since "2026-11-02 00:00:00"`.

| Resultat | Antal |
| --- | ---: |
| `journal_rows_seen` | **641** |
| `parsed_sudo_rows` | **641** |
| `command_invoked` | 214 |
| `pam_session_opened` | 214 |
| `pam_session_closed` | 213 |
| `pam_auth_failure` | 0 |
| `incorrect_password` | 0 |
| `not_in_sudoers` | 0 |
| `other_sudo` | 0 |
| `malformed_or_incomplete_metadata` | 0 |
| `sudo.repeated_auth_failure` | **0** kandidatfund |
| `sudo.permission_denied` | **0** kandidatfund |

Rettelsen af journal-scope er dermed **verificeret på Pi** for
den reelle kilde: 641/641 læste poster er strukturelt parsebare,
og normale sudo-kommandoer/PAM-sessioner udløser ikke kandidatfund.
Dette er **ikke** 641 uafhængige normale handlinger,
ikke en estimeret falsk-positiv-rate og ikke en validering
af detektorens evne til at opdage afviste sudo-forsøg.
Der er **ingen verificerede fejl-/afvisningsposter** i dette
testinterval.

Den tidligere forsøgte `sudo -n /usr/bin/true` under
`yggdrasil-web` gav exit-kode 1, men stderr blev undertrykt.
Det kan have været et manglende interaktivt password,
ikke nødvendigvis en faktisk `not_in_sudoers`-afvisning.
Næste sikre gate er **højst ét** tilsvarende, harmløst
forsøg med *lokal klassificering* af stderr i grove kategorier,
uden at udskrive rå fejltekst og uden at ændre sudoers,
brugerrettigheder, systemd, SQLite eller Discord.

### Håndtering af tidligere uafklaret `sudo -n`-fejl

`deploy/sprint5_sudo_denial_reason_probe.py` er en særskilt,
**manuelt udløst** diagnostik, der højst udfører ét
ikke-interaktivt `sudo -n /usr/bin/true` fra den allerede
eksisterende lavtprivilegerede servicekonto `yggdrasil-web`.
Det ydre sudo-kald kan forudgås af `sudo -v` som
den almindelige loginbruger for at verificere adgang
uden at ændre sudoers. Scriptet nægter at køre som root
eller med en root-targetkonto.

Stderr og stdout fra processen læses kun i hukommelsen.
Outputtet er JSON med exit-kode og **grov fejlkategori**,
eksempelvis `password_required_noninteractive`,
`not_in_sudoers`, `command_not_permitted`,
`tty_required`, `privilege_execution_blocked` eller
`unclassified_failure`. Ingen rå fejltekst,
kommandoargumenter fra journal, PID'er, UID'er,
brugernavne eller adgangskoder udskrives.

Hvis resultatet er `password_required_noninteractive`,
har sudo krævet autentificering, men `-n` kunne ikke
spørge efter adgangskoden. Det er *ikke* samme ting
som et faktisk `not_in_sudoers`-forløb.
En efterfølgende eventuel detektortest skal udvælge
en reelt logget afvisning, ikke blot en ikke-nul
exit-kode. Et ukendt resultat må ikke gættes til
en autentificeringsfejl.

Scriptet er kun et midlertidigt **diagnoseværktøj**,
ikke en ny tjeneste eller intrusion-detektor; det
ændrer ikke sudoers, systemd, SQLite eller Discord.
Tests sikrer ét fast harmløst kommandoforløb og
sanitiseret output. Kør først fra en fuld CI-godkendt
Git-commit.

### Pi-test: `sudo -n` krævede password, ikke verificeret sudoers-afvisning (3. november 2026)

Det isolerede, manuelt udløste
`deploy/sprint5_sudo_denial_reason_probe.py` blev kørt på
Yggdrasil fra commit
`53453691b8205d407becaa26cbce07ae7996bc9f`.
Den normale loginbruger verificerede sin egen sudo-adgang
med `sudo -v`, og værktøjet udførte derefter ét
ikke-interaktivt `sudo -n /usr/bin/true` via
`yggdrasil-web`. Kun sanitiseret JSON blev offentliggjort.

| Felt | Faktisk resultat |
| --- | --- |
| `status` | `completed` |
| `exit_code` | `1` |
| `reason_category` | `password_required_noninteractive` |
| `raw_stdout_stderr_exposed` | `false` |
| `sudoers_or_services_modified` | `false` |

**Konklusion:** Dette var **ikke** et dokumenteret
`not_in_sudoers`-forsøg eller en journalverificeret
`pam_auth_failure`. Det betyder alene, at sudo krævede
autentificering, som `-n` forhindrede. Den tidligere
`sudo.permission_denied=0` er derfor forventelig og ikke
bevis på en fejl i regelmotoren.

Sprint 5 fortsætter med syntetisk positive tests og
adskilt passiv sudo-journalindsamling; der er ikke behov
for yderligere bevidst fejlede sudo-forsøg på Pi på
nuværende tidspunkt. En rigtig detektionsaccept
kræver senere en valideret hændelse i et kontrolleret
testmiljø med kendt forventet logformat. Sudo-alarmer
er stadig ikke aktive på produktionsserveren.

### Sprint 5: kortvarig sudo-shadow-observation (ikke producerende service)

`deploy/sprint5_sudo_shadow_observe.py` følger **kun**
`_EXE=/usr/bin/sudo` fra alle journaler, som
`yggdrasil-worker` har adgang til, uden at ændre
den eksisterende SSH/UFW-collectors `--system`-scope.
Den kører kun ved **manuel start** i 5–60 sekunder
(standard 15) og afbryder sit `journalctl --follow`-barn
ved slutningen.

Den modtager `MESSAGE`, cursor og nødvendige metadata,
men opbevarer udelukkende et kortvarigt, hukommelsesbaseret
analysevindue. Hver post er begrænset til 64 KiB; højst
2.000 poster tælles pr. observation. Parseren genbruger
`parse_sudo` og `SudoRuleDetector` fra den isolerede
prototypemodel. Den udskriver alene grov kategori,
antal og **kandidatfund**. Der skrives intet til SQLite,
ingen sudo-/SSH/UFW-konfiguration ændres, og ingen
Discord-beskeder sendes.

Denne observation **er ikke** en installeret
sudo-detektor, selv når den genkender et syntetisk
sikkerhedsmønster. Udtrykket `shadow` betyder her
`observeret og analyseret uden alarmhandling`,
ikke den eksisterende SSH-Isolation-Forest-model.

**Accept:** GitHub CI (pytest + Ruff + wheel) på
Python 3.11 og 3.13, derefter kort manuel
Pi-observation som worker med én legitim
`sudo /usr/bin/true` fra den almindelige
loginbruger, hvis man ønsker en kontrolleret
succes-hændelse. Der er ikke brug for flere
bevidst fejlede sudo-logins.
Ingen rå logposter eller modelartefakter uploades.

### Pi-liveaccept: 15 sekunders manuel sudo-shadow-test (3. november 2026)

Brugeren kørte `deploy/sprint5_sudo_shadow_observe.py` fra
den CI-godkendte commit `94917044b657fecc9245a8e6585f74cd608c41bc`
på Yggdrasil som `yggdrasil-worker`, med en legitim
`sudo /usr/bin/true` udført under observationen.
Observationen blev afsluttet efter **15 sekunder**.

| Mål | Faktisk resultat |
| --- | ---: |
| `journal_rows_seen` / `parsed_sudo_rows` | **5 / 5** |
| `command_invoked` | 2 |
| `pam_session_opened` | 2 |
| `pam_session_closed` | 1 |
| Parse-/kvalitetsfejl | 0 |
| `sudo.permission_denied` kandidatfund | 0 |
| `sudo.repeated_auth_failure` kandidatfund | 0 |
| SQLite-skrivninger / Discord-notifikationer | **0 / 0** |

**Konklusion:** Den kortvarige live-observatør kan indsamle og
fortolke autentiske normale sudo-loglinjer på den faktiske Pi
uden alarmkandidater eller produktionsændringer.
To `command_invoked`-poster er ikke bevis for to
uafhængige administratorhandlinger: opstarten af testen
anvendte også sudo. Den ekstra `pam_session_opened` uden
tilsvarende `pam_session_closed` i tidsvinduet viser ikke
i sig selv et vedvarende login; en observation kan afskære
en logsekvens.

**Afgrænsning:** Vi har **ikke** verificeret en ægte
positiv sudo-afvisning eller PAM-auth-fejl i Pi-journalen,
og 5 normale poster giver **ikke** en meningsfuld
falsk-positiv-rate. Sprint 5's næste udviklingstrin er
en privat, adskilt, testbar hændelseslagring med
deduplikering og retention, inden en eventuel
produktionstjeneste og notifierintegration overvejes.

### Opt-in integrationstest: sudo-shadow + privat midlertidig SQLite

Den allerede beståede manuelle Pi-test verificerede den separate
sudo-shadow-monitor med **5 sudo-poster på 15 sekunder, 0
regel-kandidater og ingen produktionseffekter**. En anden,
separat Pi-test verificerede `SudoStagingStore` med syntetiske
events: oprettelse, unikhed, atomisk kandidatlagring, retention og
adskillelse fra produktionsdatabasen.

Næste trin forbinder **kun disse to testkomponenter**:
`deploy/sprint5_sudo_shadow_observe.py --stage-temporary`.

- Standardtilstand (uden flag) er **fortsat read-only og
  uden SQLite-skrivninger**.
- Med `--stage-temporary` oprettes en **ny,
  worker-ejet privat 0700-mappe** og en **0600-SQLite-fil**
  gennem `TemporaryDirectory` og `SudoStagingStore`.
  Den slettes automatisk ved afslutning, også ved fejl.
- Journalen udvælges kun på trusted `_EXE=/usr/bin/sudo`
  fra workerens tilgængelige journaler. Der er et kort
  5–60 sekunders målevindue og højst 2.000 poster.
- Kun et hash af journalcursor, tidspunkt, boot-ID,
  numerisk UID og PID, grov hændelseskategori samt
  eventuelle regelkandidater gemmes i **testdatabasen**.
  Ingen rå `MESSAGE`, `COMMAND`, usernames,
  rå journalcursors, adgangskoder eller SQLite-data
  udsendes fra scriptet.
- Rapporten viser både observerede journalrækker og
  antallet af **unikt gemte** rækker; dubletter
  registreres særskilt. `private_staging_summary`
  er kun aggregeret statistik.
- Vedvarende lagring under `/var/lib/yggdrasil-ids`,
  systemd-service, produktions-SQLite, dashboard,
  Discord-outbox, sudoers, SSH/UFW-collector og
  Isolation Forest berøres **ikke**.

**Bemærk:** Denne første prøve gemmer kun data i
målevinduet; den er ikke en driftsklar persistent
sudo-detektor. Hvis der senere ønskes permanent
sudo-lagring, skal det designes særskilt med
adgangskontrol, opstarts-checkpoints, diskbudget,
retention, backup/rollback og privat dashboardadgang.
Den nuværende regelmotor genskaber ikke automatisk
sine tidsvinduer efter en genstart.

### Pi-test: 15 sekunders sudo-shadow med privat SQLite bestået (3. november 2026)

Brugeren har kørt den isolerede `--stage-temporary`-test
på Yggdrasil som `yggdrasil-worker`, med en legitim
`sudo /usr/bin/true`. Følgende JSON-resultat blev
kontrolleret uden rå logmeddelelser:

| Kontrol | Observeret |
| --- | ---: |
| Journalposter læst / parset | **5 / 5** |
| Unikke rækker gemt privat | **5** |
| Dubletter | 0 |
| `command_invoked` | 2 |
| PAM åbnet / lukket | 2 / 1 |
| Parsefejl / replayfejl | 0 / 0 |
| Sudo regelkandidater | **0** |
| Produktionsdatabaseskrivning / Discord | **false / false** |
| Testdatabase slettet ved afslutning | **true** |

Dette verificerer kæden
`journald → _EXE-filter → parser → regelmotor → privat SQLite`
i 15 sekunder på den faktiske Raspberry Pi. Testen
dokumenterer ikke en ægte sudo-angrebsdetektion og
må ikke forveksles med en uafhængig falsk-positiv-rate.

**Næste sikkerhedsgate:** et *offline* syntetisk
genstarts-/replayforsøg med privat checkpoint,
deduplikering, fortsættelse efter afbrydelse,
atomisk kandidatlagring og begrænsning af
overlapstid. Ingen ny systemd-service eller
permanent database aktiveres som led i denne test.

### Genstarts-/replayprototype: timestamp-checkpoint i isoleret SQLite (udvikling)

**Prototype i Sprint 5-grenen, ikke installeret som service.**
Den private `SudoStagingStore` har nu schema v2 og et
`sudo_checkpoint` med **kun højeste committed
Unix-tidspunkt**. Hver ny normaliseret sudo-række,
eventuel kandidat og timestamp-watermark committes
atomisk i SQLite. Ved en fejlet kandidattransaktion
rulles alle tre tilbage.

Vi gemmer **ikke** rå journald-cursors, `MESSAGE`,
`COMMAND` eller brugernavne. En næste journalreader
kan beregne `--since` som
`last_committed_timestamp - overlap_seconds - 1`
og genafspille de overlappende journalposter. Deres
hash-baserede identiteter gør lagring idempotent.
Regelmotoren skal samtidig **genopbygges fra
replayede hændelser** for at bevare vinduer og
cooldown og undgå utilsigtet alarm efter genstart.
Overlap skal mindst dække både regelvindue og cooldown.

Den dedikerede
`deploy/sprint5_sudo_recovery_lab.py`
gennemfører tre syntetiske processessioner mod en
**ny privat, midlertidig SQLite**. Der verificeres
genstart, overlap, identiske cursorhash-dubletter,
en enkelt syntetisk regelkandidat, efterfølgende
cooldown, retention og overlevelse af checkpoint
efter sletning af gamle rækker. Ingen virkelig
sudo-journal læses og ingen produktionsfil ændres.

**Vigtig begrænsning:** Tidsstempel-overlap giver
*best effort*, **ikke fuldstændig exactly-once
eller garanti mod logtab**. Journalrotation,
større urhop, out-of-order journald-meddelelser
og lange afbrydelser kan give huller, der må
registreres som data-gap. En fremtidig
driftsklar service kræver særskilte checks af
journaltilgængelighed, sikker init/backup/rollback,
backpressure, diskbudget og systemd-livscyklus,
før den eventuelt integreres.

### Næste Pi-gate: genstart/replay på et fast snapshot af ægte sudo-journal

`deploy/sprint5_sudo_journal_restart_accept.py` er en
**manuelt kørt, afgrænset accepttest** af den isolerede
sudo-kilde. Det er ikke en installeret sensor, og den
tilføjer ikke servicekonfiguration, SQLite-schema eller
Discord-data til den aktive IDS.

Scriptet kører som `yggdrasil-worker`, læser kun
`_EXE=/usr/bin/sudo` i tilgængelige journaler og
fryser en 1–48 timers historisk tidsperiode
(standard 24 timer, højst 3.000 poster pr. læsning).
Den indledende scanning bruger udelukkende tidsstempler
til at vælge et todelt testinterval. Tre efterfølgende
journal-læsninger bruger en **privat, midlertidig
worker-ejet SQLite** og *nye* `SudoRuleDetector`-instanser
for hver simuleret processtart.

Første fase indlæser den ældre halvdel. Anden fase
fortsætter fra checkpoint minus 300 sekunder (+1 sekund
overlap), med tidligere poster gentaget og senere
poster nyindlæst. Tredje fase genafspiller slutningen
endnu en gang og kræver 0 nye gemte rækker og 0 nye
kandidater. Samtidig kontrollerer scriptet, at antallet
af unikke rows i databasen svarer til snapshot-antallet.

**Output er kun aggregerede tal.** Rå sudo-MESSAGE,
kommandoer, username, UID/PID, cursor, boot-ID og
filsystemstier offentliggøres ikke. Arbejdsdatabasen
slettes, før resultatet udskrives; ingen handlinger
køres med root ud over eksisterende eksplicit
autoriseret journaladgang via worker.

**Bestået test betyder kun:** replay/checkpoint og
deduplikering fungerede for det frosne historiske
journal-snapshot. Det er **ikke** et bevis på tabsfri
langtidsdrift, journalrotation, suspend/reboot,
store tidsændringer, overload eller en korrekt
sikkerhedsalarm ved et virkeligt angreb.

### Pi-accept: 402 sudo-poster over tre simulerede genstarter (3. november 2026)

Den isolerede, manuelt kørte `deploy/sprint5_sudo_journal_restart_accept.py`
har læst **402 eksisterende sudo-journalposter** fra et fast
24-timers historisk snapshot som `yggdrasil-worker`. En privat
midlertidig SQLite blev anvendt til tre genafspilningsfaser.

| Kontrol | Resultat |
| --- | ---: |
| `result` | `success` |
| Første indlæsning: nye poster | 201 |
| Anden indlæsning: nye poster | 201 |
| Anden indlæsning: dubletter | 183 |
| Tredje indlæsning: nye poster | **0** |
| Tredje indlæsning: dubletter | 3 |
| Unikke rækker i privat SQLite | **402** |
| `sudo.permission_denied` / `sudo.repeated_auth_failure` | **0 / 0** |
| Midlertidig database slettet | `true` |
| Produktionsdatabase ændret / Discord | `false / false` |

**Resultat:** Den private lagring dækker alle 402 unikke
journalposter fra dette **faste, historiske** datagrundlag
og opretter ingen nye rækker ved tredje replay. De tre
dubletter i sidste gennemløb skyldes den korte
checkpoint-overlapperiode, ikke blot at hele historikken
blev læst igen.

**Afgrænsning:** Der er fortsat **ingen faktisk, verificeret
afvist sudo-handling** i disse data, så en sudo-alarm er
ikke demonstreret. Testen må ikke kaldes bevis for
tabsfri genstart af en vedvarende `journalctl --follow`-service.
Dette er nu tilstrækkelig infrastrukturafprøvning til at
påbegynde en **kontrolleret negativ sudo-test i et isoleret
lab** og eventuelt installere en adskilt shadow-sensor efter
særskilt sikkerhedsgennemgang. Undgå at forsøge at fremkalde
mange PAM-fejl på produktionskontoen `vidar` eller
IDS-servicekontiene.

### Ubuntu-VM-accept: verificeret sudo-auth-burst fra ægte journalposter (3. november 2026)

Et isoleret angrebslaboratorium `ubuntu-gateway` (Ubuntu
24.04.5 LTS, Python 3.12.3) på labnettet `10.77.77.0/24`
blev anvendt. `labadmin` oprettede en separat låst
`ids-sudo-lab`-konto i sudo-gruppen og udførte **tre
kontrollerede mislykkede sudo-kald**. Ingen rigtige
adgangskoder eller angreb mod produktionsværten blev brugt.

En første journalaudit af VM'en gav 29 sudo-poster,
3 `pam_unix(sudo:auth): authentication failure`,
3 `incorrect password attempts`-opsummeringer og
0 `not_in_sudoers`.

Den rigtige `src/yggdrasil_ids/sudo_rules.py` fra
Sprint 5-branchen blev derefter overført via en
særskilt SSH-nøgle fra `yggdrasil` til VM'en, og
genafspillet mod eksisterende journald-JSON uden
ændringer af VM'ens IDS-tjenester eller databaseskema.

**Faktisk replay-resultat:**

| Måling | Verificeret |
| --- | ---: |
| Sudo-journalposter læst | **30** |
| `pam_auth_failure` | **3** |
| `incorrect_password` | **3** |
| Forskellige fejlede sudo-processer | **3** |
| Parsefejl | **0** |
| `sudo.repeated_auth_failure`-kandidater | **1** |
| `sudo.permission_denied`-kandidater | **0** |
| Produktions-IDS ændret | **Nej** |
| Discord-beskeder sendt | **Ingen** |

**Dette er den første dokumenterede positive
detektoraccept med rigtige, kontrolleret fremkaldte
sudo-fejl i VM'en.** Den tæller ikke PAM-failure og
sudo-password-summary som to uafhængige forsøg,
da tre forskellige proces-ID'er udløser præcis
én `sudo.repeated_auth_failure`-kandidat.
De 30 er journalposter og ikke 30 angrebsforsøg.

**Afgrænsning:** Dette er *historisk replay*, ikke en
live-alert, måling af detektionslatens eller
produktions-FPR. Den offentlige GitHub-repo rummer
ingen private rå journalposter eller passwords.
Næste gate er en **kortvarig live shadow-kørsel på VM'en**
med en ny, autoriseret tre-forsøgsserie for
at måle realtidsdetektionen, før man overvejer
persistent driftsintegration eller Discord.

### Ubuntu-VM liveaccept: autentisk sudo-auth-burst opdaget under observation (3. november 2026)

Den eksisterende `sudo_rules.py`, `sudo_storage.py` og
`sprint5_sudo_shadow_observe.py` blev overført til den
isolerede VM via den særskilte SSH-nøgle, uden at ændre
Yggdrasil-produktionens tjenester eller åbne netværksadgang.
`labadmin` verificerede sin sudo-adgang, startede en
**25-sekunders** shadow-observation med
`--stage-temporary` og udførte tre nye kontrollerede,
fejlede sudo-forsøg under `ids-sudo-lab`-testkontoen.

| Verificeret måling | Faktisk resultat |
| --- | ---: |
| `journal_rows_seen` / `parsed_sudo_rows` | **21 / 21** |
| `pam_auth_failure` | **3** |
| `incorrect_password` | **3** |
| `command_invoked` | 3 |
| `pam_session_opened` / `pam_session_closed` | 3 / 3 |
| `other_sudo` (genkendt som øvrig sudo) | 6 |
| `not_in_sudoers` | 0 |
| `sudo.repeated_auth_failure` | **1 kandidat** |
| `sudo.permission_denied` | 0 |
| Private unikke SQLite-rækker | **21** |
| Private dubletter | 0 |
| Parser- og replaykvalitetsfejl | **0** |
| Midlertidig SQLite slettet | `true` |
| Produktionens SQLite / Discord berørt | `false` / `false` |

**Faglig konklusion:** En **rigtig live-dataflow-test**
har verificeret `journalctl --follow` → betroet sudo-`_EXE`
→ Python-parser → regelmotor → privat SQLite. Tre separat
fejlede sudo-processer udløste **præcis én**
`sudo.repeated_auth_failure`-kandidat under
observationen, mens både PAM- og password-summary-linjer
blev fortolket uden at fordoble procesantallet.
`other_sudo=6` betyder kendt kilde med uklassificeret
tekstformat, **ikke** seks parsefejl.

**Dette er ikke** en verificeret Discord-meddelelse,
alvorlighedsgrad-validering mod en større angriberdatabase,
måling af præcis alarm-latens, eller dokumentation af
falsk-positiv-rate for produktionen. Kontrollen
demonstrerer én positiv, kontrolleret lab-sekvens.
Der blev ikke delt rå sudo-journaltekst eller credentials.

**Næste fase:** etabler en særskilt, gated alarmkæde
fra sudo-kandidater til rapportering, der kan testes
med en lokal/falsk notifikationsafsender og en privat
DB-kopi. Først derefter vurderes, om en
produktionsnotifikation skal aktiveres. Eksisterende
SSH/UFW-collector, Isolation Forest og Discord-secret
må ikke flyttes eller ændres ved et labforsøg.

### Discord-forhåndsvisning på ægte VM-logs: to uafhængige sudo-forløb (3. november 2026)

En manuel offline-preview på `ubuntu-gateway`, som genanalyserer
eksisterende journald-hændelser fra `2026-11-03 00:00:00`,
gav **72 sudo-journalposter**, `malformed_or_untrusted=0`,
og **to** `sudo.repeated_auth_failure`-kandidater.
Der var ingen `sudo.permission_denied`-kandidater.
Brugeren kørte preview-kommandoen **to gange**, men
previewen er stateless og genanalyserer historikken fra
start **ved hver kørsel**. Tallet 2 svarer til de to
tidligere separate kontrollerede sudo-fejlserier; det
betyder **ikke**, at hver kørsel skabte to nye
vedvarende alarmer, og slet ikke fire Discord-beskeder.

Den redigerede besked blev dannet af den eksisterende
`DiscordNotifier.message`, nu med dansk sudo-label,
`medium` og neutral henvisning til den autoriserede
sudo-journal. Den indeholdt ingen rå kommandoer,
brugeridentiteter eller adgangskoder.
**`discord_messages_sent=0`** og
**`webhook_read=false`**. Dette var kun én
forhåndsvisning af den første kandidat og **ingen
levering**.

### Isoleret SQLite-outbox → fake-Discord-integration

`deploy/sprint5_sudo_outbox_lab.py` forbinder
**for første gang** en sudo-kandidat fra den rigtige
`SudoRuleDetector` til en separat, midlertidig
`Repository`-database med `alerts` og den
eksisterende `discord_outbox`-trigger. En separat
`DiscordNotifier` bootstrappes **før** nye alarmer
indskrives. `poll()` anvender en eksplicit injiceret
**falsk sender** og en syntetisk, ubrugelig
Discord-lignende webhook. Der foretages ingen netværkskald.

Alle SQLite-filer, fake webhook og notifier-checkpoint
ligger i `TemporaryDirectory` og slettes før
rapportering. Output indeholder kun aggregater
og højst én redigeret eksempelbesked. Der skrives
**aldrig** til produktions-IDS, dens notifier-state,
Discord-secrets eller til den aktive webhook.
Ingen nye sudo-forsøg er nødvendige; testens
`--since` genbruger eksisterende VM-historik.

**Acceptkriterier:** Med de to kontrollerede serier skal
der være 2 kandidater → 2 midlertidige alerts →
2 outbox-events → 2 fake-leveringer med pending=0,
samt `discord_messages_sent=0` og
`temporary_databases_deleted=true`.
Det er en arkitekturtest af outbox/notifier med
falsk sender, **ikke** en faktisk Discord-levering.

**Videre mod virkelig Discord:** Integrér senere en
begrænset sudo-eventstream i Yggdrasils eget
alarmdataskema med en kontrolleret, opt-in
migrations-/rollbackplan. Lab-VM'en får **aldrig**
produktions-Discord-webhook; en virkelig
notifikation må kun leveres fra den adskilte
notifier på den betroede server.

### Bilag S5-A – Screenshot af to `sudo.repeated_auth_failure`-fund

**Status: Screenshot optaget ifølge ejeren, men selve billedet er
endnu ikke modtaget, visuelt gennemgået eller uploadet til
GitHub.** Bevar den originale billedfil lokalt som
eksamensbilag. Skel mellem billedets indhold og
terminalmålingerne, som allerede er verificeret.

**Verificeret terminalgrundlag (3. november 2026):**
Den historiske sudo-Discord-preview og den efterfølgende
isolerede outbox-test fandt hver **2**
`sudo.repeated_auth_failure`-kandidater i de samme
**72** journald-poster fra `ubuntu-gateway`.
Outbox-testen gav **2 midlertidige `alerts`**,
**2 outbox-poster**, **2 leveringer til en falsk
afsender**, **0 afventende** og **0 rigtige
Discord-beskeder**. Brugeren oplyser at have taget
et screenshot af de to sudo-fund; billedet
supplerer terminalresultaterne, men må ikke beskrives
som dokumenteret visuel evidens, før det er kontrolleret.

**Foreslået billedtekst i eksamensrapporten:**

> Bilag S5-A – To detekterede forløb med gentagne
> sudo-autentificeringsfejl i isoleret Ubuntu-laboratorium.
> Yggdrasil IDS' regelmotor identificerede to
> `sudo.repeated_auth_failure`-kandidater ved replay
> af virkelige, kontrollerede journald-hændelser.
> Test af SQLite-outbox og notifier anvendte en falsk
> Discord-afsender; ingen meddelelser blev sendt til Discord.

**Før rapportbrug:** Kontroller at billedet rent faktisk viser
begge fund, og at læseren kan se testens kontekst.
Slør eventuelle brugernavne, hjemmemapper, IP-adresser,
terminalhistorik, SSH-nøgler, adgangskoder, tokens og
webhook-URL'er. Bevar gerne tidspunkt, detektor-ID og
det samlede antal fund. Undlad at lade et billede
af dry-run-output fremstå som et screenshot af en
reelt leveret Discord-besked.

**Bilag S5-B (supplerende):** Den aggregerede JSON
fra den isolerede outbox-test dokumenterer
`temporary_alert_rows=2`, `temporary_outbox_rows=2`,
`fake_notifier_deliveries=2`,
`discord_messages_sent=0` og
`temporary_databases_deleted=true`.

### Forberedt: enkelt virkelig Discord-LABTEST fra betroet Yggdrasil-notifier

`deploy/sprint5_sudo_discord_delivery_smoketest.py` skaber
et helt **midlertidigt** schema-v4-IDS med **én tydeligt
mærket, simuleret sudo-kandidat**, og kører den gennem
de allerede eksisterende `alerts` → `discord_outbox`
→ `DiscordNotifier.poll()`-komponenter.
Standardkørsel bruger en *falsk afsender* og giver
**aldrig** et netværkskald.

En virkelig meddelelse kan **kun** sendes med **begge**
`--send-real --confirm-lab-message`, og kun som
systembrugeren `yggdrasil-notifier`. Den må køres
fra en **ny, kortvarig, isoleret systemd-testservice**
med `LoadCredential=discord-webhook.url:/etc/yggdrasil-ids/discord-webhook.url`.
Hemmeligheden bliver på Raspberry Pi'en, ikke i
GitHub, terminaloutput eller `ubuntu-gateway`.
De oprindelige produktionsservices og databaser
stoppes/ændres ikke. Alle test-SQLite-filer slettes
før output. Ingen sudo-loginfejl fremprovokeres.

**Præcis hvad sådan en bestået test dokumenterer:**
en reelt modtaget **LAB-MÆRKET** Discord-besked
fra Yggdrasils egen notifierkode, med én
syntetisk sudo-kandidat indsat i en privat
test-outbox. Den dokumenterer **ikke** en
automatisk Discord-levering af VM'ens to
tidligere angrebsfund, og er **ikke** bevis for
en aktiveret permanent sudo-detektor.

**Skærmbillede S5-07:** Tag både beskeden i
Discord (med tydelig `SUDO LABTEST`-markering)
og terminal-JSON med `mode=real_discord`,
`notifier_acknowledged=1`, `notifier_pending=0`,
`production_database_modified=false`,
`temporary_databases_deleted=true`.
Gem originaler lokalt og vælg senere.
Ingen credentials/webhook-URL på billeder.
Se `docs/SCREENSHOT_CANDIDATES.md`.

### Manuel Pi-test af virkelig Discord-transport – gated runner, ikke udsendt endnu

`deploy/sprint5_sudo_discord_pi_lab_send.sh` er en
**manuelt aktiveret** wrapper. Den verificerer en
fast Git-SHA, at `yggdrasil-notifier.service`
er aktiv, og at testkode kun kommer fra en
verificeret udviklingscommit. Først køres
`sprint5_sudo_discord_delivery_smoketest.py`
offline med en falsk afsender og en ny privat
SQLite-outbox. Derefter kræves den **eksakte**
terminalbekræftelse `SEND`.

Ved bekræftelse starter wrapperen en **enkelt kortvarig
systemd-unit**, under `yggdrasil-notifier` og med
`LoadCredential` fra den eksisterende lokale
webhook. Unitten bruger en række sandbox-properties,
en privat temp-SQLite og afsluttes efter præcis
én meddelelse til Discord (eller fejl).
Ingen produktionsservice genstartes, og hverken
VM'en, SSH/UFW eller den aktive SQLite får
skriverettigheder til webhooken. Kun testkoden,
udtrukket til en kortvarig læsbar `/tmp`-mappe,
kører i transient testunit; mappen slettes bagefter.

**Vigtigt metodisk skel:** Det sendte event er
**syntetisk, men alarmformatet og Discord-leveringen
er rigtige**. Discord-beskedens serverfelt er
`Yggdrasil – SUDO LABTEST (ikke produktionsalarm)`.
Denne prøve beviser *ikke* automatisk
VM-attack → Yggdrasil-prod-alarm → Discord.
Det kræver en senere særskilt integration med
autoriseret kilde, dedup/checkpoint, persistence og
rollback.

**Screenshot S5-07:** Gem eventuelt både den rigtige
Discord-besked med `SUDO LABTEST` og terminalens
`mode=real_discord`, `notifier_acknowledged=1`,
`temporary_databases_deleted=true`. Undlad
webhook-URL og andre hemmeligheder. Der kan
gemmes flere kandidater; kun de stærkeste skal
udvælges til selve eksamensrapporten.

### Pi-accept: rigtigt sudo-LABTEST Discord-ack (3. november 2026)

En manuel test på Yggdrasil anvendte den eksisterende
systemd-beskyttede notifierkonto via
`deploy/sprint5_sudo_discord_pi_lab_send.sh`
fra commit `e5a6947c21dcc7b7010cb9f64cc9c56706fea3d8`.
Først bestod scriptets **offline fake-sender-test**
med én midlertidig test-outbox-hændelse, hvor
`real_discord_send_attempted=false`.
Brugeren indtastede derefter eksplicit `SEND`, og
den kortvarige systemd-enhed afsluttede med
`result=success`, `status=0/SUCCESS`.

**Faktisk verificeret:** `mode=real_discord`,
`real_discord_send_attempted=true`,
`real_discord_acknowledged=true`,
`notifier_acknowledged=1`,
`notifier_pending=0`,
`temporary_outbox_events=1`,
`temporary_databases_deleted=true`,
`production_database_modified=false`,
`production_notifier_state_modified=false`,
`ubuntu_gateway_contacted=false`,
`webhook_value_exposed=false`. Brugeren
bekræftede også, at Discord-beskeden faktisk kom frem.

Dette er en **rigtig leveringsprøve af en
syntetisk, tydeligt mærket `SUDO LABTEST`-alarm**.
Det er **ikke** en automatisk notifikation, som
blev udløst af et faktisk sudo-logevent. Den aktive
produktions-IDS registrerer endnu ikke sudo-fund
i den delte `alerts`-tabel. Normal sudo-brug
skal heller ikke skabe alarmsignal, hvis der
ikke er et mistænkeligt mønster.

**Screenshots:** Brugeren nåede ikke at tage
screenshot ved første levering, men kan tage et
af den eksisterende Discord-kanalbesked, hvis
den stadig findes. En gentagen manuel test
kan sende en ny besked: hver kørsel har sin egen
midlertidige outbox/notifier-state og **ingen
delt test-cooldown**. Undgå unødvendige
dubletbeskeder. Registrér screenshot som S5-07
først efter faktisk modtagelse og gennemgang.

### Klargøring til permanent shadow-sensor: Pi-journal og separat timer (3. november 2026)

**Verificeret læseadgang under `yggdrasil-worker`:**
`yggdrasil-collector.service`,
`yggdrasil-web.service` og
`yggdrasil-notifier.service` var alle `active`.
Worker-brugeren havde grupperne
`yggdrasil-data systemd-journal`.
En *læsebaseret* 24-timers forespørgsel
(`journalctl --all --output=json _EXE=/usr/bin/sudo`)
gav **411 sudo-journalposter**, hvor **alle 411**
havde de seks nødvendige metadatafelter, og
**0** var `pam_unix(sudo:auth): authentication failure`.
Dette er et journalinventar og **ikke** en målt
falsk-positiv-rate eller et bevis på, at alle 411
poster opfylder den fulde parser-validering.
Resultatet er foreneligt med normal drift uden
registrerede PAM-sudo-fejl.

**Ny udviklingskode (ikke installeret endnu):**

- `deploy/sprint5_sudo_shadow_poll.py`:
  isoleret one-shot scanner af
  `_EXE=/usr/bin/sudo`, uden `--system`,
  **ingen netværk**, ingen Discord, og
  ingen produktions-IDS-database.
- `SudoStagingStore` gemmer kun normaliserede
  kategorier, proces-/UID-/bootmetadata,
  hændelsestid og SHA-256 af journald-identiteten
  i **privat worker-ejet SQLite**.
- En separat `shadow_poll_checkpoint` angiver
  seneste **fuldførte** journalinterval.
  Hver kørsel genafspiller et overlappende interval
  for at rekonstruere regelvinduet og cooldown.
  **Afbrudt journallæsning gemmer ingen nye poster
  og flytter ikke interval-checkpointet**.
- Kørsel er afgrænset til maksimalt
  **3.000 poster og 20 sekunders journalindlæsning**.
  En afbrydelse over 48 timer eller et tilbagespring
  i systemuret giver en eksplicit fejl og kræver
  gennemgang, ikke stille datatab.
- `deploy/yggdrasil-sudo-shadow.service`:
  **en oneshot-service** med separat
  `StateDirectory` mode `0700`,
  `User=yggdrasil-worker`,
  `PrivateNetwork=true`, ingen capabilities.
  `deploy/yggdrasil-sudo-shadow.timer`
  er kun et forslag til at køre omtrent hvert minut.
- `deploy/sprint5_sudo_shadow_probe_pi.sh`:
  først en **manuel accept** med to på hinanden
  følgende polls mod Yggdrasils rigtige sudo-journal.
  Kode og privat SQLite er midlertidige og slettes
  automatisk; de eksisterende services berøres ikke.

**Vigtig regression:** En første CI-test fandt,
at et afbrudt journalstream kunne efterlade
en normaliseret hændelse uden den senere beregnede
alarmkandidat ved retry. Implementationen blev
ændret til at validere og beregne samtlige
maksimalt 3.000 poster i hukommelsen **før**
SQLite-skrivning. Først når journalstreamen
afsluttes uden fejl, starter persisteringen.
Dette er et dokumenteret eksempel på, hvordan
CI og enhedstests fandt en relevant
sikkerhedsmæssig fejl i recovery.

**Aktiveringsgrænse:** Dokumentationen og CI
godkender *ikke* installation på Pi af sig selv.
Først skal den manuelle worker-probe bestå
(`mode=shadow`, anden kørsel genkender checkpointet,
ingen nye dobbeltgemte poster,
`discord_alerts_sent=0`).
Kun derefter udarbejdes og gennemgås en
eksplicit installation/rollback. Produktionens
collector, web, notifier, SQLite og Discord
forbliver uændret indtil videre.

### Pi-shadow baseline: tomt 15-minuttersvindue (3. november 2026)

Brugeren kørte den CI-verificerede to-poll-test
`deploy/sprint5_sudo_shadow_probe_pi.sh` som
`vidar` på Yggdrasil fra commit
`10bc6c4f8f17b2e228bd3f1459e45403273faa2d`.
Begge kørselers JSON viste
`mode=shadow`, `journal_rows_read=0`,
`new_normalized_sudo_rows=0`,
`new_candidate_rule_matches=0`,
`discord_alerts_sent=0` og
`production_database_modified=false`.
Den anden kørsel rapporterede
`previous_checkpoint_present=true`;
`temporary_staging_deleted=true` og
alle tre produktions-IDS-tjenester var fortsat aktive.

**Konklusion:** Ingen fejlagtige alarmer eller
produktionsændringer, og initialisering/genoptagelse
af checkpoint er demonstreret i et tomt tidsvindue.
Testen kan **ikke** påvise korrekt
logindlæsning eller dubletfjernelse på Pi,
fordi der var **nul** sudo-hændelser i de første
15 minutter af sensorens søgevindue. De tidligere
411 sudo-journalposter stammer fra et helt døgn
og modsiger ikke et tomt kvartersvindue.

Derfor er testwrapperen i udviklingsbranchen
ændret til at **afvise positiv accept**, hvis
`first_poll.journal_rows_read=0` eller
`second_poll.overlap_duplicates_skipped=0`.
En sikker opfølgende test skal fremkalde
**én almindelig vellykket** `sudo /usr/bin/true`
(ingen fejl eller rettighedsændringer),
lade journald registrere posten og gennemføre
to worker-ejede polls igen. Først med
faktiske poster i begge polls kan vi erklære
deduplikering af rigtig Pi-journal bestået.

**Eksamensscope:** Efter afsluttet regelbaseret
sudo-sensor og nødvendig validering fryses
nye IDS-features for denne eksamen.
Filintegritetsovervågning/FIM og eventuel
yderligere ML for sudo er udsat til efter eksamen.
Eksisterende Isolation Forest på SSH forbliver
i shadow-mode; netværksscanning forbliver
regelbaseret.

### Pi-accept: normal sudo-hændelse, checkpoint og deduplikering (3. november 2026)

Efter et almindeligt, vellykket `sudo /usr/bin/true` på
Yggdrasil kørte ejeren `deploy/sprint5_sudo_shadow_probe_pi.sh`
fra commit `4636d7c9019e951ecd13d10a8e7bfc2ad8d481db`.
Den worker-ejede, **midlertidige** database blev slettet
efter testen. Begge polls brugte den samme private DB
under forsøget og læste autentiske journald-data:

| Måling | Første poll | Anden poll |
| --- | ---: | ---: |
| `journal_rows_read` | **3** | **3** |
| `new_normalized_sudo_rows` | **3** | **0** |
| `overlap_duplicates_skipped` | 0 | **3** |
| `previous_checkpoint_present` | `false` | **`true`** |
| `command_invoked` | 1 | 1 |
| `pam_session_opened` | 1 | 1 |
| `pam_session_closed` | 1 | 1 |
| Sudo-alarmkandidater | **0** | **0** |

Yderligere verificeret i output:
`production_services_modified=false`,
`production_database_modified=false`,
`discord_messages_sent=0`,
`temporary_staging_deleted=true`.
Dette er en **bestået positiv Pi-accept af
normal journalindlæsning, genoptaget checkpoint
og deduplikering**. Vi har fortsat ikke målt
24-timers oppetid med en permanent timer eller
produceret en ny vellykket sudo-detektoralarm på Pi.
Positiv detektion med tre autentificeringsfejl
er tidligere demonstreret **i isoleret Ubuntu-VM**,
ikke ved at påvirke produktionskontoen.

**Screenshot S5-10:** Tag `second_poll`, så
`previous_checkpoint_present=true`,
`journal_rows_read=3`,
`new_normalized_sudo_rows=0` og
`overlap_duplicates_skipped=3`
ses samtidigt. Bevar originalen til senere udvælgelse.

### Stage → aktivering → rollback: begrænset systemd-shadow-sensor

Efter denne accept er tre scripts udviklet:

1. `deploy/sprint5_sudo_shadow_install_pi.sh`:
   kræver pinned og verificeret Git-commit samt
   tre aktive eksisterende IDS-tjenester.
   Stager **kun** de nødvendige sudo-kildefiler
   root-ejet i `/opt/yggdrasil-sudo-shadow/`,
   en `COMMIT`-manifestfil og en selvstændig
   `yggdrasil-sudo-shadow.service` +
   `yggdrasil-sudo-shadow.timer` i systemd.
   Kører `systemd-analyze verify`, men **aktiverer
   hverken timer eller service**.
2. `deploy/sprint5_sudo_shadow_activate_pi.sh`:
   sammenligner hvert installeret kilde- og
   enhedsindhold med pinned commit. Starter
   **én** servicekørsel og kræver `Result=success`,
   før timeren aktiveres med `enable --now`.
   Kontrollerer, at de tre eksisterende services
   stadig er aktive. Ved fejl efter timerstart
   deaktiveres timeren igen.
3. `deploy/sprint5_sudo_shadow_rollback_pi.sh`:
   deaktiverer og stopper **kun** sudo-shadow-unitten,
   fjerner de stagerede kildefiler og units
   og genindlæser systemd. Den worker-ejede
   SQLite-testhistorik bevares til audit, medmindre
   ejeren senere særskilt beslutter at slette den.

**Driftsgrænser:** oneshot via systemd-timer omtrent
én gang/minut, `PrivateNetwork=true`,
`NoNewPrivileges=true`, `ProtectSystem=strict`,
`User=yggdrasil-worker`, privat
`StateDirectoryMode=0700` med særskilt
`/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3`.
Koden indeholder ingen webhook, og den eksisterende
Discord-notifier kender **ikke** sudo-sensoren endnu.
Ingen `sudo`-fund er derfor koblet til
produktions-`alerts` eller dashboard i denne fase.

**Inden stage:** godkend CI på pinned SHA,
kontrollér at de tre normale IDS-tjenester er
aktive, og stop hvis der allerede findes en
shadow-installation. Efter stage: bekræft
`timer started=NO` og `timer enabled=NO`.
Først derefter aktiveres den særskilt og
kontrolleres for fejl. Særlig fejlbehandling
kræves for journald-gap over 48 timer og
pludselige systemurændringer; ingen komplet
lossless-recovery-garanti er hævdet.

**Eksamensscope:** Når sudo er afsluttet,
fryses udviklingen af nye IDS-sensorkilder;
FIM/filintegritet og ekstra ML udskydes til
efter eksamen. Prioritér evaluering af regler,
Isolation Forest og falske positiver i rapporten.

### Pi-accept: manuel sudo-shadow systemd-oneshot bestået (3. november 2026)

Efter installation af root-ejet kode og systemd-units fra
pinned kildecommit `6b662fe07c85b2c4caa34129c8cac0f2146b9b80`
rapporterede ejeren:

- Installation: `shadow code and units staged successfully`,
  `Shadow timer started: NO`, `Shadow timer enabled: NO`.
- **Manuel** `systemctl start yggdrasil-sudo-shadow.service`
  gennemførtes med `Result=success`, `ExecMainStatus=0`,
  `ActiveState=inactive` (*forventet* for oneshot).
- Faktisk worker-ejet sudo-poll:
  `mode=shadow`, `journal_rows_read=54`,
  `new_normalized_sudo_rows=54`,
  `overlap_duplicates_skipped=0`,
  `previous_checkpoint_present=false`.
- De 54 poster fordelte sig i
  **18 `command_invoked`**,
  **18 `pam_session_opened`** og
  **18 `pam_session_closed`**.
  **0** `pam_auth_failure`,
  **0** `incorrect_password`,
  **0** `not_in_sudoers`,
  **0** kandidatmatch af begge sudo-regler.
- `private_staging_summary.persisted_log_rows=54`,
  `private_database_only=true`,
  `production_database_modified=false`,
  `discord_alerts_sent=0`.
- Shadow timeren var fortsat **`inactive`**.

**Accept:** En reel, vellykket systemd-start med journaladgang
og privat persistering af 54 normale sudo-poster er
demonstreret. Dette er **ikke** dokumentation for en
aktiv vedvarende timer, længere oppetid eller en
automatisk Discord-alarm fra sudo.

**Screenshot S5-11:** Gem et billede med
`Result=success`, `ExecMainStatus=0`,
`journal_rows_read=54`, `mode=shadow`,
`discord_alerts_sent=0` og eventuelt
`timer=inactive`. Screenshotfilen er endnu
ikke gennemgået her.

**Næste, særskilt aktiveringsgate:** Kør den pinned
`deploy/sprint5_sudo_shadow_activate_pi.sh`
fra **den installerede commit `6b662fe07...`**.
Den kontrollerer kildens integritet,
gennemfører endnu en oneshot, og først derefter
`systemctl enable --now` for den isolerede
sudo-shadow-timer. Ved fejl kan timeren stoppes med
`sudo systemctl disable --now yggdrasil-sudo-shadow.timer`.
Der sker ingen tilsigtet ændring af produktions-SSH,
UFW, ML, web eller notifier.

### Pi: sudo-shadow timer enabled (user confirmation, further operation pending)

After a successful manual systemd oneshot (54 normalized sudo rows; no
candidates; no Discord), the user reported that running the pinned
`sprint5_sudo_shadow_activate_pi.sh` produced the expected result:
`sudo shadow timer enabled and active`,
`Notification state: SHADOW ONLY (no Discord/outbox)`,
and the original collector, dashboard and notifier remained active.
**This is user-confirmed summary, not a captured full terminal output.**

Next acceptance gate: independently inspect `systemctl is-enabled/is-active`,
actual timer schedule and multiple subsequent oneshot executions. Verify
the worker-owned SQLite checkpoint advances and old sudo journal rows are
not duplicated. No need to induce sudo authentication failures on the
production Pi; controlled positive detection is already validated in the
Ubuntu lab. Record screen evidence only after checking the returned output.

### Pi: periodisk sudo-shadow-timer og privat SQLite verificeret (3. november 2026)

En selvstændig read-only kontrol efter aktivering viste:

| Kontrol | Faktisk observation |
| --- | --- |
| `systemctl is-active yggdrasil-sudo-shadow.timer` | **`active`** |
| `systemctl is-enabled yggdrasil-sudo-shadow.timer` | **`enabled`** |
| Næste/seneste timerløb (CET) | **10:52:35 / 10:51:35** |
| `Result` / `ExecMainStatus` for oneshot | **`success` / `0`** |
| Private `sudo_signals`-rækker | **69** |
| Private `sudo_candidates`-rækker | **0** |
| Worker-checkpoint | **2026-11-03T10:51:33.296639+01:00** |
| `command_invoked` / `pam_session_opened` / `pam_session_closed` | **23 / 23 / 23** |
| Fejl (`pam_auth_failure`, `incorrect_password`, `not_in_sudoers`) | **0 / 0 / 0** |

**Resultat:** Timeren havde en planlagt efterfølgende kørsel, sensoren
afsluttede med systemd `success`, og den særskilte private database
indeholder 69 normaliserede sudo-hændelser fra normal drift. Ingen
sudo-kandidater blev fundet i dette udsnit. Journalposter er **ikke**
uafhængige sudo-handlinger: 69 poster omfatter bl.a. 23
kommandohændelser med tilhørende session open/close.
Dette er dokumentation for kortvarig periodisk drift
og normal registrering, **ikke** målt false-positive-rate,
langtidsstabilitet eller live sudo→Discord-kæde.

**Screenshot S5-12:** Ejeren blev bedt om at gemme
`active`, `enabled`, `Result=success`,
`Gemte sudo-hændelser: 69`,
`Alarmkandidater: 0` og sidste checkpoint.
Faktisk screenshotfil er endnu ikke gennemgået eller uploadet.

**Resterende lukningsgate:** Lav en læsebaseret SQLite-`integrity_check`,
verificér worker-ejerskab og private mode på sudo-state,
og kontrollér at de tre hidtidige IDS-tjenester fortsat er
aktive. Derefter kan Sprint 5 afsluttes som **regelbaseret sudo-sensor
i shadow-mode**, og ny featureudvikling udsættes til efter eksamen.
En senere live sudo-alarm kræver særskilt integreret
alarm-/outbox-deployment og positiv driftsaccept; de to
eksisterende realtidsdetektioner er fra isoleret Ubuntu-VM.

### Afsluttet: privat SQLite-integritet, permissions og eksamensscope (3. november 2026)

Efter periodisk drift bestod den sidste read-only Pi-kontrol med
**alle fire relevante enheder active**
(`yggdrasil-collector.service`, `yggdrasil-web.service`,
`yggdrasil-notifier.service`, `yggdrasil-sudo-shadow.timer`).
Den worker-ejede sudo-shadow-mappe var `0700`, SQLite-filen `0600`,
`PRAGMA integrity_check=ok`, **75** lagrede normaliserede sudo-poster
og **0** alarmkandidater. Kommandoen sluttede med `RESULTAT: PASS`.
Der blev ikke gennemført nye sudo-fejlforsøg, sendt Discord-alarmer
eller ændret den eksisterende produktionsdatabase.

**Sprint 5 erklæres afsluttet i den aftalte eksamensafgrænsning:**
regelbaseret sudo-observation med separat, aktiv systemd-timer
**i shadow-mode**. En automatisk sudo→`alerts`→Discord-pipeline
er **ikke** aktiveret og må ikke præsenteres som gennemført;
den tidligere rigtige Discord-levering var en mærket simuleret LABTEST.
Der er ikke målt en produktions-FPR eller langtidsoppetid.
Fremtidig FIM/filintegritet og sudo-ML udsættes til efter eksamen.

En kort samlet resultattabel, begrænsninger og screenshot-kandidater
findes i [Sprint 5-afslutningen](SPRINT_5_CLOSEOUT.md).

### Sudo-Isolation-Forest: sidste aftalte eksamensfunktion under udvikling

Den regelbaserede sudo-shadow-sensor er stabilt testet,
men Sprint 5 er **ikke endeligt afsluttet med ML**.
På brugerens præcisering fortsætter vi
udelukkende med den **oprindeligt planlagte sudo-Isolation-Forest**,
hvorefter der fryses for nye IDS-funktioner inden eksamen.
FIM/filintegritet udskydes til efter eksamen.

`src/yggdrasil_ids/sudo_ml.py` indeholder en
**separat** `SudoIsolationForest` med et fast 7-feature
procesbaseret skema. `deploy/sprint5_sudo_ml_lab.py`
opretter kun syntetisk normaltræning,
adskilte validerings- og låste testscenarier,
og måler regler kontra ML på **samme** forsøg.
`deploy/sprint5_sudo_ml_run_pi.sh`
er en manuel pinned-SHA-wrapper, som kun
bruger privat output under hjemmemappen.
Ingen model er installeret i produktions-sudo-sensoren,
og ingen sudo-ML-alarmer er aktive.

**Før Pi-test:** kræv CI-bestået. Efter syntetisk
evaluering kontrolleres datadækning på **rigtige**
sudo-journalposter i ren shadow/readonly-tilstand.
Se [design, features og vurderingskriterier](SPRINT_5_SUDO_ML.md).
