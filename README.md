# Yggdrasil IDS

Python-baseret sikkerhedsovervågning til en privat Linux-server. Yggdrasil IDS
indsamler relevante journalposter, vurderer dem, gemmer alarmhistorik og sender
nye alarmforløb til Discord. Et loginbeskyttet dansk dashboard viser hændelser,
alarmer, grafer, SSH-modelvurderinger og driftsstatus.

Målmiljøet er Raspberry Pi 5 med Debian 13 og Python 3.13. Udvikling og tests
kan køres på Linux med Python 3.11 eller nyere.

## Detektion

| Område | Metode | Hvad der overvåges |
| --- | --- | --- |
| SSH-autentificering | Regler + Isolation Forest | Fejlede og vellykkede autentificeringer, brugernavne og afvigende aktivitet pr. kilde |
| SSH-preauth | Regler | Gentagne understøttede afbrydelser før autentificering |
| Portscanning | Regler | Blokerede indgående TCP SYN-pakker til flere destinationsporte i UFW-loggen |
| Sudo | Regler | Gentagne autentificeringsfejl på tværs af processer og sudoers-afvisninger |

Programmet ændrer ikke firewallregler, blokerer ikke adresser og ændrer ikke
SSH- eller sudoers-konfigurationen. En alarm er et fund, der kræver vurdering;
den er ikke bevis for en gennemført indtrængen.

## Produktionsversion

Denne version samler driftskode, installation, automatiserede tests og vejledninger.
Forsøgsprogrammer, separate preview-servere og historiske benchmarkpaneler er
fjernet fra produktet. Udviklingsforløb og målinger er bevaret på
[eksperimentbranchens fastlåste reference](https://github.com/Nox699/AI-Intrusion-Detection-System/tree/6abbc5d849973a9b15b2565ec7d25d66cc4effd8).

SSH-modellen skal være trænet, kunne indlæses og være aktiveret til alarmer.
Der følger ingen privat model eller virkelige logdata med Git-repoet. Den
samlede Pi-opgradering kontrollerer den eksisterende models identitet og
bevarer dens træningsgrundlag og tærskel; den træner ikke på nye livehændelser.
Sudo og portscanning anvender ingen ML-model.

Den samlede release blev installeret på Yggdrasil den 4. november 2026.
Kontrollerede liveforløb viste SSH-ML, SSH-regler, preauth, TCP-portscanalarmer
og sudo-regelalarmer i det fælles dashboard. Discord-modtagelse er brugerbekræftet
for SSH-ML-, portscan- og sudo-testene. Resultater og resterende beviskontroller fremgår af
[ACCEPTANCE.md](docs/ACCEPTANCE.md); de er ikke en måling af generel
detektionsrate eller falsk-positiv-rate.

## Installation og drift

Følg [Pi-installationen](deploy/INSTALL_PI.md) for den samlede installation eller
opgradering. Den bruger separate servicekonti, en fælles produktionsdatabase,
en privat sudo-sensor og den eksisterende Discord-alarmkø.

Dashboardet lytter på **`127.0.0.1:8765`**. Opret en tunnel fra laptoppen, og
erstat kontoen og værtsnavnet med din servers oplysninger:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:8765:127.0.0.1:8765 minbruger@min-server
```

Åbn derefter `http://127.0.0.1:8765` i browseren. Indsamlingen og Discord-
leveringen fortsætter uafhængigt af browseren.

Se [driftsvejledningen](docs/OPERATIONS.md) for servicekontrol, modelstatus,
backup, retention og fejlsøgning. [Sikkerhedsgrænserne](docs/SECURITY.md)
beskriver journaladgang, private data og webadgang.

## Udvikling og automatiserede tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps --editable .
.venv/bin/python -m pytest
node --test tests/nav_alerts.test.cjs
```

Tests bruger kontrollerede lokale data og lokale erstatninger for eksterne
services. De starter ikke angreb mod Pi'en og sender ikke Discord-beskeder.
Se [TESTING.md](docs/TESTING.md) for testtyper og validering af releasen.

## Kode og dokumentation

- [Arkitektur og objektorientering](docs/ARCHITECTURE.md)
- [Drift og modelhåndtering](docs/OPERATIONS.md)
- [Test og CI](docs/TESTING.md)
- [Sikkerhed og dataadgang](docs/SECURITY.md)
- [Accept og eksamensbeviser](docs/ACCEPTANCE.md)

Isolation Forests afvigelsesscore er ikke en angrebssandsynlighed. Modellen og
reglerne dækker bestemte logmønstre; løsningen lover hverken alle angreb fundet,
tabsfri journalhistorik eller en målt generel detektionsrate.
