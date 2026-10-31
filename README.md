# Yggdrasil IDS

**Sprint 1 · SSH-overvågning med regler, Isolation Forest og et dansk dashboard.**

Python-applikation til privat SSH-overvågning på Linux, med Raspberry Pi 5,
Debian 13/ARM64 og almindelig OpenSSH over Tailscale som målmiljø. Udvikling og
demonstration kan køres i Ubuntu/WSL. Collector og dashboard kører uafhængigt,
så indsamlingen fortsætter, når browseren lukkes.

**Status:** Sprint 1 er implementeret og softwaretestet. Accepttest på den
konkrete Pi afventer. Se [verifikationen](docs/VERIFICATION.md),
[Pi-installationen](deploy/INSTALL_PI.md) og [roadmap](docs/ROADMAP.md).

## Indhold

- Løbende journalindsamling med vedvarende læseposition og genstart uden dubletter.
- Succesfulde og fejlede SSH-autentificeringer, herunder `sshd-session`.
- Tre konfigurerbare regler: mange fejl, mange brugernavne, uventet vellykket login.
- Isolation Forest med dokumenterede features, modelversion og afvigelsesscore.
- SQLite-historik, grupperede alarmer og hændelsesdetaljer.
- Loginbeskyttet dashboard med filtre, grafer, modelvisning og driftsstatus.
- Isoleret demonstration, reproducerbart labforsøg og automatiserede tests.
- Systemd-filer, installationsvejledning og en konkret plan for accepttest på Pi'en.

Discord er planlagt til sprint 2. Netværk/portscanning, sudo og filkontrol står
på backloggen; rækkefølgen er endnu ikke fastlagt.
Programmet ændrer ikke firewall, SSH-konfiguration eller Tailscale og blokerer
ikke adresser automatisk.

## Hurtig start i WSL eller på Linux

Krav: Git, Python 3.11 eller nyere og `python3-venv`. Internet er nødvendigt
til at hente kildekode, runtime-afhængigheder og byggeafhængigheder.
Dashboardet henter derefter ingen skrifttyper, scripts eller grafer fra en CDN.

```bash
git clone https://github.com/Nox699/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps .
.venv/bin/yggdrasil-ids demo --directory .demo
.venv/bin/yggdrasil-ids serve --config .demo/config.toml
```

Installationen bygger pakken direkte fra kildekoden; en `dist/`-mappe er ikke
nødvendig. `requirements.lock` fastlåser runtime-versionerne. Pips isolerede
byggetrin henter desuden setuptools og wheel efter `pyproject.toml`.

Åbn **http://127.0.0.1:8765**. Demo-adgangskoden er **`demo-yggdrasil`**.
Det er en offentlig kendt adgangskode til den isolerede lokale demonstration.
Rigtig drift kræver en egen adgangskode oprettet med kommandoen `credentials`.
Dashboardet markerer demonstrationsdata tydeligt. `demo` afviser en eksisterende
ikke-tom mappe; brug en ny mappe for et nyt forsøg.

På en Windows-laptop åbnes adressen normalt direkte i Windows-browseren, når
applikationen kører i WSL. Hvis lokal videresendelse er deaktiveret i din WSL,
skal den kontrolleres som en del af din opsætning. Ændr ikke bindingen til
`0.0.0.0` for at komme uden om dette.

## Første rigtige opsætning

Demoen er et selvstændigt datagrundlag. Opret en separat konfiguration og database
til Pi'en. I projektmappen kan en udviklingsopsætning oprettes sådan:

```bash
cp config.example.toml config.toml
.venv/bin/yggdrasil-ids init --config config.toml
.venv/bin/yggdrasil-ids credentials --config config.toml
.venv/bin/yggdrasil-ids doctor --config config.toml --journal
```

`credentials` spørger interaktivt efter adgangskoden; den sendes ikke som et
kommandolinjeargument. Relative filstier i TOML fortolkes i forhold til
konfigurationsfilen. Drift med separate servicebrugere beskrives i
[installationsvejledningen](deploy/INSTALL_PI.md).

Start collector og web i hver sin terminal ved en manuel afprøvning:

```bash
.venv/bin/yggdrasil-ids collect --config config.toml
```

```bash
.venv/bin/yggdrasil-ids serve --config config.toml
```

Collector kræver læseadgang til systemjournalen. Kør ikke hele webapplikationen
som root. Driftsvejledningen giver journaladgang til en separat collector-bruger.

### Adgang fra laptop gennem Tailscale

Webserveren lytter på Pi'ens loopbackadresse. Opret en tunnel fra laptoppen,
eksempelvis i Windows PowerShell eller WSL. **Erstat `minbruger` og `min-pi`**
med Linux-kontoen og serverens Tailscale-navn eller Tailscale-IP:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8765:127.0.0.1:8765 minbruger@min-pi
```

Åbn derefter **http://127.0.0.1:8765** på klienten. Kommandoen bruger almindelig
OpenSSH over Tailscale. Ingen ny indgående
webport behøver at blive åbnet. Hvis lokal port 8765 allerede bruges af demoen,
stop demoen eller brug fx lokal port 8766 i venstre side af `-L`.

## Regler og forventet normal brug

Standardforslagene er 5 fejlede autentificeringer eller forsøg mod 4 forskellige
brugernavne fra samme kilde inden for 300 sekunder. De er justerbare eksempler,
ikke dokumenterede optimale grænser for dit netværk.

`expected_sources` og `expected_users` er tomme fra start. Den tilsvarende kontrol
af vellykkede logins er slået fra, indtil du har valgt en profil. Indsæt fx din
laptops aktuelle Tailscale-adresse som `/32` og de forventede Linux-konti. En tom
profil må ikke præsenteres som bevis for, at alle succesfulde logins er normale.

Tællingerne er **autentificeringsforsøg**, ikke forbindelser, bots eller angreb.
En SSH-klient kan afprøve flere nøgler i én forbindelse. PAM-sessionsåbning og
`Invalid user`-forvarsler tælles ikke som ekstra autentificeringer.

## Machine learning

Modellen er valgfri under indsamling af normaldata. En manglende eller ugyldig
model er synlig, og reglerne fortsætter. Applikationen træner ikke automatisk på
ukendt trafik. Modellen bruger pr. kilde det bagudrettede tidsvindue
`(hændelsestid − window_seconds, hændelsestid]` og disse features:

1. Antal fejlede autentificeringer.
2. Antal vellykkede autentificeringer.
3. Antal forskellige brugernavne.
4. Andel af fejlede autentificeringer.
5. Sinus for UTC-klokkeslættet.
6. Cosinus for UTC-klokkeslættet.

En ny observation beregnes ved hver autentificeringshændelse. IP-adresser og
brugernavne bliver ikke omsat til vilkårlige tal. Højere modelscore betyder mere
afvigende aktivitet; scoren er **ikke en angrebssandsynlighed**. `contamination`
styrer en modelgrænse og angiver ikke en målt angrebsandel.

### Gentag laboratorieforsøget

```bash
.venv/bin/yggdrasil-ids lab --directory .lab
```

Forsøget opretter separate trænings-, validerings- og testforløb samt en kort
rapport med fund, falske alarmer og oversete hændelser. Kun normale træningsdata
bruges til at tilpasse modellen. Hele scenarier holdes adskilt med tidsafstand
større end to analysevinduer. Forventningerne står ved siden af logdata og
sendes ikke til modellen som features. Testdata bruges ikke til at justere
grænser. Resultatet er en **syntetisk demonstration af software og metode**.

I `examples/lab/` ligger syntetiske input med dokumentationsadresser og rapport
fra et allerede gennemført forsøg.
Kør `lab --directory examples/lab` for at gentage netop disse input; rapport og
laboratoriemodel opdateres i denne mappe. Et nyt lab genererer tider i forhold til
kørselstidspunktet, så dets konkrete scores kan afvige. Den medfølgende model
beskriver kun laboratoriedata og er ikke en model af din rigtige SSH-brug.

### Træn på gennemgåede data

Udvælg et normalt JSONL-forløb fra journalen, og gem andre hele tidsperioder til
validering/test. Bevar journalfelterne `_COMM`, `_UID`, `__REALTIME_TIMESTAMP`
og `__CURSOR`. Eksport fra `journalctl -o json` indeholder disse felter.

```bash
.venv/bin/yggdrasil-ids prepare-training normal-ssh.jsonl --config config.toml --output normal-features.json
.venv/bin/yggdrasil-ids train normal-features.json --config config.toml --provenance "Gennemgået normal SSH-brug i den angivne periode"
```

Træning kræver tilstrækkeligt mange og varierede observationer. Data bliver ikke
bedre af blot at gentage den samme række. På en rolig privat server kan et egnet
datagrundlag tage længere tid at opbygge. Laboratoriemodellen skal derfor ikke
ukritisk flyttes til rigtig drift.

Modellen gemmes som valideret JSON med numeriske træningsobservationer og
indstillinger. Ved indlæsning genskabes skoven med samme seed og scikit-learn-
version. Der indlæses ingen pickle/joblib-filer. SHA-256-fingeraftrykket opdager
utilsigtede ændringer; det er ikke en digital signatur eller beskyttelse mod en
angriber med skriveadgang til modellen.

Brug `--replace` ved bevidst udskiftning af en eksisterende model. Genstart
collector for at aktivere den. Historiske hændelser genscores ikke i den samme
database; brug et nyt isoleret forløb til en sammenligning af modelversioner.

## Drift og vedligeholdelse

- `doctor --config ... --role collector --journal` og `doctor --config ... --role web`
  kontrollerer de relevante krav for hver servicebruger. En vellykket root-kontrol
  beviser ikke, at collector-brugeren kan læse journalen. Uden `--role` kontrolleres
  både web og collector, hvilket passer til en lokal udviklingsopsætning.
- `backup --config ... --output backup.sqlite3` tager en konsistent SQLite-backup
  uden at overskrive en eksisterende fil.
- `prune --config ...` anvender retention manuelt og kræver, at collector er
  stoppet. Collector håndhæver retention løbende hver time. Sletning frigør plads
  til genbrug inde i SQLite; filen krymper ikke nødvendigvis på disken.
- `credentials --config ... --replace` ændrer adgangskode og sessionsnøgle.
  Genstart webprocessen og kontrollér rettigheder som i driftsvejledningen.
- Cursor, records, hændelser, analyser og alarmer gemmes atomisk. Hvis den gamle
  journalposition er roteret væk, genoptages fra det seneste tidspunkt med
  overlap, og et muligt hul i data vises tydeligt.
- Forsinkede hændelser gemmes, men analyseres ikke bagudrettet. Tidsproblemer
  vises som datakvalitetsproblemer. Overvågningens korrekthed afhænger også af
  Pi'ens ur og de tilgængelige journalposter.

## Udvikling og tests

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
```

`docs/VERIFICATION.md` beskriver den gennemførte kontrol af den leverede version.
`docs/TEST_ON_PI.md` beskriver de nødvendige lokale afprøvninger. En grøn testpakke
i udviklingsmiljøet dokumenterer ikke automatisk logdækning, ydeevne eller
detektionskvalitet på den konkrete Pi.

## Projektets struktur

| Område | Filer |
| --- | --- |
| Domæne og konfiguration | `domain.py`, `config.py` |
| Logkilde og fortolkning | `source.py`, `ssh.py` |
| Regler og model | `rules.py`, `features.py`, `ml.py` |
| Sammenhæng og lagring | `engine.py`, `storage.py` |
| Brugerflade | `web.py`, `templates/`, `static/` |
| Administration og forsøg | `cli.py`, `lab.py` |
| Drift og forklaring | `deploy/`, `docs/` |

Se [arkitektur](docs/ARCHITECTURE.md), [sikkerhedsgrænser](docs/SECURITY.md),
[accepttest](docs/TEST_ON_PI.md) og [roadmap](docs/ROADMAP.md) for ansvar,
begrænsninger og næste skridt. Projektets egen kode er udgivet under
[MIT-licensen](LICENSE). Afhængigheder har deres egne licenser.
