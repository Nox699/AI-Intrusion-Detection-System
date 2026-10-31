# Installation på Raspberry Pi

Denne vejledning gælder **første installation** på en Raspberry Pi med Debian
13/ARM64. Kildekoden hentes direkte fra projektets repository. Bevar en
fungerende SSH-session under afprøvningen. Ingen af trinnene ændrer SSH,
Tailscale eller firewallregler. Hvis disse tjenestenavne eller konfigurationsfiler
allerede findes, skal den eksisterende installation gennemgås før en opdatering.

## 1. Python og program

Kontrollér miljøet, og installer Python-miljøet. `venv` oprettes på Pi'en; kopiér
ikke en `.venv` fra Windows, WSL eller en anden processorarkitektur.

```bash
cat /etc/os-release
uname -m
python3 --version
sudo apt update
sudo apt install git python3-venv
git clone https://github.com/Nox699/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System
git rev-parse HEAD
sudo install -d -o root -g root -m 0755 /opt/yggdrasil-ids
sudo python3 -m venv /opt/yggdrasil-ids/venv
sudo /opt/yggdrasil-ids/venv/bin/python -m pip install --only-binary=:all: -r requirements.lock
sudo /opt/yggdrasil-ids/venv/bin/python -m pip install --no-deps .
sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids --version
```

Fortsæt de følgende trin fra den klonede projektmappe. Notér commit-ID’et fra
`git rev-parse HEAD`, så installationens kildekode kan identificeres. Pakken
bygges fra kilden; en `dist/`-mappe er ikke nødvendig. Runtime-afhængighederne
er fastlåst i `requirements.lock`. Pips isolerede byggetrin henter desuden
setuptools og wheel efter `pyproject.toml`, også når `--no-deps` bruges.

De låste afhængigheder er kontrolleret for tilgængelige Python 3.13/ARM64-wheels.
Det er ikke en gennemført test af din hardware eller dine logs. Python 3.11+
understøttes af projektet; de gennemførte kontroller står i [verifikationen](../docs/VERIFICATION.md).

## 2. Separate servicekonti

Opret to konti uden interaktivt login. Collector må skrive til dataområdet og
læse journalen. Webkontoen får læseadgang til data, men ingen journalgruppe.

```bash
sudo groupadd --system yggdrasil-data
sudo groupadd --system yggdrasil-web
sudo useradd --system --gid yggdrasil-data --groups systemd-journal --home-dir /var/lib/yggdrasil-ids --no-create-home --shell /usr/sbin/nologin yggdrasil-worker
sudo useradd --system --gid yggdrasil-web --groups yggdrasil-data --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin yggdrasil-web
sudo install -d -o yggdrasil-worker -g yggdrasil-data -m 2750 /var/lib/yggdrasil-ids
sudo install -d -o root -g yggdrasil-data -m 0750 /etc/yggdrasil-ids
sudo install -o root -g yggdrasil-data -m 0640 deploy/config.pi.toml /etc/yggdrasil-ids/config.toml
id yggdrasil-worker
id yggdrasil-web
```

Gruppen `systemd-journal` giver bred journaladgang; SSH-filtreringen i programmet
er ikke i sig selv en rettighedsbegrænsning. Webkontoen skal ikke tilføjes til
gruppen. Dataområdets setgid-bit bevarer gruppen på nye filer.

## 3. Normalprofil og dashboardlogin

```bash
sudoedit /etc/yggdrasil-ids/config.toml
```

Behold `bind = "127.0.0.1"`. Både `expected_users` og `expected_sources` er
tomme fra start; hver tom liste slår den tilsvarende kontrol af vellykkede logins
fra. Angiv de Linux-konti, som forventes at logge ind, og eventuelt kendte
klienters aktuelle Tailscale-IP med `/32` for IPv4 eller `/128` for IPv6.
En Tailscale-adresse beviser ikke, hvilken person der bruger enheden.

Eksempel på syntaks i den eksisterende `[rules]`-sektion:

```toml
expected_users = ["minbruger"]
expected_sources = ["192.0.2.10/32"]
```

`minbruger` og dokumentationsadressen `192.0.2.10` er pladsholdere, som skal
erstattes med gennemgåede værdier fra installationen. Opret ikke en ekstra
`[rules]`-sektion. Bevar tomme lister, hvis en profil endnu ikke er besluttet.

Opret din egen adgangskode interaktivt. CLI gemmer hash og en tilfældig sessionsnøgle:

```bash
sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids credentials --config /etc/yggdrasil-ids/config.toml
sudo chown root:yggdrasil-web /etc/yggdrasil-ids/web-secrets.json
sudo chmod 0640 /etc/yggdrasil-ids/web-secrets.json
sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/yggdrasil-ids init --config /etc/yggdrasil-ids/config.toml
sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/yggdrasil-ids doctor --config /etc/yggdrasil-ids/config.toml --role collector --journal
sudo -u yggdrasil-web /opt/yggdrasil-ids/venv/bin/yggdrasil-ids doctor --config /etc/yggdrasil-ids/config.toml --role web
```

Fortsæt, når database, web og journaladgang er godkendt for de relevante konti.
`Ingen model` er forventet under indsamling af normaldata; reglerne kan køre.
En aktiv heartbeat er først forventet, når tjenesten er startet. Hvis journal-
kontrollen fejler, undersøg læseadgangen; gør ikke journalen offentligt læsbar.

SQLite bruger rollback-journal (`DELETE`) og korte transaktioner. Det gør, at
webkontoen kan læse historikken fra et skrivebeskyttet dataområde, også når
collector er stoppet. Webkontoen skal ikke have skriverettighed til databasen.

## 4. Installer og start tjenester

```bash
sudo install -o root -g root -m 0644 deploy/yggdrasil-collector.service /etc/systemd/system/yggdrasil-collector.service
sudo install -o root -g root -m 0644 deploy/yggdrasil-web.service /etc/systemd/system/yggdrasil-web.service
sudo systemd-analyze verify /etc/systemd/system/yggdrasil-collector.service /etc/systemd/system/yggdrasil-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now yggdrasil-collector.service yggdrasil-web.service
systemctl status yggdrasil-collector.service yggdrasil-web.service --no-pager
sudo journalctl -u yggdrasil-collector.service -u yggdrasil-web.service -n 50 --no-pager
sudo ss -lntp 'sport = :8765'
```

Webserveren skal kun lytte på `127.0.0.1:8765`. Collector læser lokale journalfiler
og har et privat netværksnavnerum. Webserveren kører via Gunicorn med én worker
og fire tråde. Dens separate kontrolsocket er deaktiveret. Systemd begrænser
filsystemadgang, hukommelse og procesantal; en uventet fejl giver genstart, indtil
systemds startgrænse nås. Gentagne opstartsfejl kræver fejlsøgning.

## 5. Åbn fra din laptop

Luk den lokale demo, hvis den bruger port 8765. Kør på laptoppen i PowerShell
eller WSL, og bevar tunnelen åben. **Erstat `minbruger` og `min-pi`** med den
rigtige Linux-konto og serverens Tailscale-navn eller Tailscale-IP:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8765:127.0.0.1:8765 minbruger@min-pi
```

Åbn
**http://127.0.0.1:8765** og brug din egen dashboardadgangskode. En lokal port
8766 kan bruges i venstre side af `-L`, hvis 8765 allerede er optaget. Der skal
ikke åbnes en ny webport i router, UFW eller Tailscale.

Følg derefter [accepttesten](../docs/TEST_ON_PI.md). En normal SSH-autentificering er nødvendig
for at bekræfte, at netop din OpenSSH-version skriver et understøttet logformat.
Et grønt journaladgangstjek alene beviser ikke SSH-dækning.

## Vedligeholdelse

### Adgangskodeskift

`credentials --replace` opretter af sikkerhedshensyn en ny fil med mode `0600`.
Gendan derfor webgruppens læseret efter udskiftningen, og genstart webprocessen:

```bash
sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids credentials --config /etc/yggdrasil-ids/config.toml --replace
sudo chown root:yggdrasil-web /etc/yggdrasil-ids/web-secrets.json
sudo chmod 0640 /etc/yggdrasil-ids/web-secrets.json
sudo systemctl restart yggdrasil-web.service
```

### Model

Brug gennemgåede normaldata og separate testforløb som beskrevet i README.
Træn som `yggdrasil-worker`, så modellen bevarer den rigtige ejer. Filer, som
leveres til workerens træningskommando, skal være læsbare for denne konto.
Modellen skal ligge på den konfigurerede sti med ejer
`yggdrasil-worker:yggdrasil-data` og må ikke være skrivbar for webkontoen.
Genstart collector bevidst efter en godkendt modeludskiftning.

### Backup

Vælg altid et nyt backupnavn. Kommandoen bruger SQLite-backupfunktionen og afviser
overskrivning. Backupfilen kan indeholde IP-adresser og brugernavne.

```bash
sudo install -d -o root -g root -m 0700 /var/backups/yggdrasil-ids
sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids backup --config /etc/yggdrasil-ids/config.toml --output /var/backups/yggdrasil-ids/first-verified.sqlite3
```

Konfiguration, model og loginoplysninger skal sikkerhedskopieres separat med
tilsvarende begrænset adgang. Afprøv en gendannelse til en separat mappe først.
En eventuel gendannelse af driftsdatabasen kræver stoppede tjenester og korrekte
ejere/rettigheder; erstat ikke en database, mens collector skriver til den.

### Opdatering og rollback

Tag backup og noter den installerede version. Gennemgå releaseændringer før
opdatering; installér ikke blot vilkårlige nyere afhængigheder i driftsmiljøet.
Stop tjenesterne før udskiftning af program/afhængigheder, bevar konfigurationen,
og kør rolleopdelte `doctor`-kontroller og accepttest igen. Gem den tidligere
kildekodeversion og dens `requirements.lock`; en lokalt bygget wheel kan også
arkiveres som installationsartefakt. Version 0.1.0 har ingen automatisk
databaseskemamigration; et ukendt skema afvises i stedet for at blive ændret.

Ved fejl: læs `journalctl` og dashboardets systemstatus. `systemctl reset-failed`
efterfulgt af `start` er relevant, når en gentagen opstartsfejl er rettet. Undgå at
løse rettighedsfejl ved at køre webserveren som root eller gøre dataområdet
verdensskrivbart.
