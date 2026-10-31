# Verifikation af Yggdrasil IDS 0.1.0

**Gennemført 31. oktober 2026. Resultat: 336 tests bestået, 0 fejl og 0 sprunget over.**

Dette dokument skelner mellem den leverede softwares testresultater og den
accepttest, der skal udføres på Yggdrasil. Der er ikke oprettet forbindelse til
Pi'en, ændret firewallregler eller sendt Discord-beskeder under udviklingen.

## Miljø og pakke

- Linux x86_64, Python 3.12.14, pytest 9.2.0.
- scikit-learn 1.8.0, Flask 3.1.3 og Gunicorn 25.3.0.
- Produktionens dependency-versioner står i `requirements.lock`.
- Python-miljøet genbrugte præinstallerede numeriske pakker med de angivne
  versioner. Der hævdes ikke en installationstest af et helt nyt Debian-system.
- Den oprindelige sprintleverance blev bygget som wheel, installeret og startet
  gennem dens `yggdrasil-ids`-kommando. Kildekode og webressourcer blev sammenlignet
  byte for byte med den daværende kildekode. SHA-256 i
  `reports/release-verification.json` gælder denne oprindelige release, før
  repositoryets eksempelkonto og adresser blev anonymiseret.
- Pip har uden installation på Pi'en løst alle 16 låste produktionsafhængigheder
  som wheels til CPython 3.13/Linux ARM64. Det bekræfter tilgængelige pakker,
  ikke afprøvet ARM64-kørsel.

## Automatiserede tests

Efter klargøring til det offentlige repository er alle 336 tests kørt igen og
bestået med 0 fejl og 0 oversprungne tests. Ruff-kontrol og formatkontrol bestod.
Denne kørsel er dokumenteret i `reports/repository-verification.json` og
`reports/pytest-results.xml`. Den oprindelige releasekørsel er bevaret i
`reports/release-pytest-results.xml`. GitHub Actions er konfigureret til Python
3.11 og 3.13; der er endnu ingen gennemført CI-kørsel i repositoryet.

Den afsluttende kørsel tog cirka 9 sekunder i udviklingsmiljøet. Det er testpakkens
kørselstid og ikke et mål for alarmforsinkelse. Resultater pr. test findes i
`reports/pytest-results.xml`.

| Område | Tests | Centrale kontroller |
| --- | ---: | --- |
| Administration/CLI | 21 | Init, loginfiler, sikker erstatning, demo, eksport, træning og backup. |
| Konfiguration | 29 | Typer, grænser, ukendte felter, private bindinger og stier. |
| Analysepipeline | 17 | Transaktioner, genstart, dubletter, sene hændelser og modelfejl. |
| Features | 16 | Tidsvinduer, samtidige hændelser, kildeadskillelse og numeriske værdier. |
| Laboratorieforsøg | 17 | Tidsadskilte scenarier, labels, reproducerbarhed og metrikker. |
| Isolation Forest | 41 | Træning, validering, modelversion, score og sikkert JSON-format. |
| Regler | 27 | Tærskler, brugernavne, CIDR-profiler og forklarlige fund. |
| Journalindsamling | 18 | Cursor, enkelt collector, bounded input og procesfejl. |
| SSH-parser | 67 | Accepted/Failed, sshd-session, afsenderfelter og PAM-dedup. |
| SQLite | 23 | Atomisk lagring, gruppering, backup, retention og skrivebeskyttet læsning. |
| Web | 60 | Login, CSRF, sessionsudløb, XSS, filtre, sideskift og fejlvisning. |
| **I alt** | **336** | **Alle bestået.** |

Journaltesten bruger også en rigtig lokal subprocess, der efterligner
`journalctl` og leverer kontrollerede poster. Den afprøver strømmen, heartbeat og
fejltilstande uden at læse en rigtig servers journal. Den er derfor ikke bevis
for dækning af Pi'ens konkrete OpenSSH-logs.

Læseadgangstesten gør dataområdet reelt skrivebeskyttet og læser det uden en
aktiv writer. Den ville springe over i et miljø, som omgår Unix-rettigheder;
den kørte og bestod i dette miljø. Ruff-kontrol og Ruff-formatkontrol bestod.

## Afprøvning i browser

Den oprindelige releases installerede wheel blev kørt med Gunicorn på `127.0.0.1`. Chromium
140.0.7339.16 blev styret med Playwright 1.55.0. Følgende forløb bestod:

- Login med demoens adgangskode, beskyttet dashboard og logout.
- Reelle tællinger fra SQLite og to renderede Plotly-serier.
- Periodevalg, sideskift frem/tilbage og filtrering på fejlede autentificeringer.
- Udfoldning af den oprindelige SSH-meddelelse og åbning af alarmdetaljer.
- Modelvisning og systemstatus.
- Desktopvisning på 1440 pixels og mobilvisning på 390 pixels.
- Mobilmenu, ingen utilsigtet vandret sideoverløb på overblikket og afvist API
  efter logout.

Den afsluttende browserkørsel havde **ingen JavaScript-fejl, konsolfejl eller
forespørgsler til eksterne webadresser**. Graferne fungerede med den leverede CSP.
Skærmbilleder blev visuelt gennemgået internt. Mobilvisning betyder her en lille
browserbredde; der er ikke udført en test på en fysisk telefon.

Browserkontrollen fandt og førte til rettelser af CSRF/referrer-samspillet,
periodevalgets template-kontekst og paginering. Relevante regressionstests er
med i de 60 webtests. Det afsluttende resultat findes i
`reports/browser-check.json`.

Browserkontrollen er fra den oprindelige release. Klargøringen til det offentlige
repository ændrer eksempelkontoen, testadresser og dokumentation; dashboardets
kode og webressourcer er uændrede. Der er ikke kørt en ny browserkontrol af denne
dokumentations- og dataændring.

## Kontrolleret metodeforsøg

`examples/lab/` indeholder et gennemført syntetisk forsøg med 312 normale
træningsobservationer, 44 valideringsobservationer og 41 sluttestobservationer.
Scenarier holdes tidsmæssigt adskilt. Træning anvender ikke validering eller test.

| Sluttest: 19 simuleret mistænkelige og 22 normale hændelser | Regler | Isolation Forest |
| --- | ---: | ---: |
| Opdagede mistænkelige hændelser | 12 | 18 |
| Oversete mistænkelige hændelser | 7 | 1 |
| Alarmer ved normal aktivitet | 1 | 3 |
| Precision | 92,3 % | 85,7 % |
| Recall | 63,2 % | 94,7 % |
| Falsk positiv-rate | 4,5 % | 13,6 % |

Tælleenheden er autentificeringshændelser før gruppering til alarmforløb.
Overlappende observationsvinduer gør hændelserne afhængige. Første forsøg i et
simuleret forløb kan ligge under en regelgrænse og derfor tælle som overset.
Resultaterne beskriver kun disse konstruerede forløb. De viser en mulig afvejning
mellem flere fund og flere falske alarmer; de dokumenterer ikke en generel
overlegenhed for ML eller en bestemt sikkerhed på Pi'en. Rapporten beskriver også
scenarier, som den ene metode overser.

## Resterende accepttest på Pi'en

Følg `deploy/INSTALL_PI.md` og `docs/TEST_ON_PI.md`. Følgende er endnu ikke
verificeret på målsystemet:

1. Faktisk ARM64-kørsel, systemd-sandboxing og servicekontienes rettigheder.
2. Pi'ens konkrete SSH-logformater, journalretention og genstartsdækning.
3. Tailscale/SSH-tunnelen og Windows/WSL's lokale adgang.
4. Målt alarmforsinkelse, ressourceforbrug og mindst 24 timers drift.
5. Detektionskvalitet på gennemgåede data fra dit eget miljø.

Systemd-filer og installationskommandoer er gennemgået mod koden. En egentlig
`systemd-analyze verify` kunne ikke gennemføres her, fordi testmiljøets systemd-
omgivelser ikke er tilgængelige. Vejledningen indeholder kontrollen til Pi'en.
Versionen er en testet sprintleverance klar til lokal installation og accepttest;
den er ikke certificeret eller dokumenteret fejlfri i produktion.
