# Automatiserede tests og releasekontrol

Unit tests er en del af produktionskodenes kvalitetssikring og skal blive i
repoet. Fjernelsen af de tidligere forsøgsprogrammer betyder, at deres
særskilte tests fjernes eller omskrives til tests af den aktive funktion.
Kontrollerede syntetiske fixtures i `tests/` er fortsat nødvendige: de gør
resultater reproducerbare uden private data, rigtig journaladgang eller Discord.

## Lokal kørsel

Fra repositoryroden:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps --editable .
.venv/bin/python -m pytest
node --test tests/nav_alerts.test.cjs
.venv/bin/python -m ruff check src tests deploy
.venv/bin/python -m ruff format --check src tests deploy
.venv/bin/python -m build --wheel --no-isolation
```

Node-testen bruger den indbyggede test-runner og kræver ingen npm-pakker.
Runtime- og testafhængigheder er fastlåst i `requirements.lock` og
`requirements-dev.txt`. Produktionsprogrammerne skal ikke køres som root;
eventuelle mocks af brugeridentitet i en testfixture ændrer ikke runtimekravet.

## Hvad der testes

| Lag | Eksempler på kontroller |
| --- | --- |
| Parsing | Betroede journalfelter, korrekte kategorier, ukendt/fejlformet input, afgrænsede værdier og spoofingforsøg |
| Features og regler | Kildegruppering, tidsvinduer, deduplikering, grænseværdier, preauth og adskillelse af hændelsestyper |
| SSH-ML | Featureformat, model-fingerprint, versionskrav, træningsvariation, scoring, gemt tærskel og ML-fund |
| Lagring | Transaktioner, migration, historik, alarmgrupper, outbox-identitet og retention |
| Sudo | Privat lagring, procesgruppering, checkpoint, genstart, regeloverførsel og anonym eksport |
| Web | Login/CSRF, readonly-adgang, filtre, alarmdetaljer, modelstatus, stale/unavailable-tilstande og browserens læstmarkering |
| Notifier | Kø- og kildeidentitet, kvitteringer, begrænsede retries, fejl og bevaret leveringshistorik |
| Opgradering | Forhåndskontrol, samlet skift af roller, modelbevaring, beskyttede backups og rollback uden at overskrive ny historik |

En unit test kontrollerer et afgrænset ansvar, typisk med kendte input og
uden eksterne services. Integrationstests kontrollerer samarbejdet mellem
eksempelvis parser, SQLite, alarm og outbox eller mellem web og readonly-data.
Begge typer kan køres med pytest; `unittest`-modulet er ikke et krav for at
skrive unit tests.

## CI og fortolkning

CI installerer de fastlåste afhængigheder og kører format/lint, syntakskontrol,
pytest, navigationens JavaScript-tests og wheel-build. Workflowet definerer de
understøttede Python-versioner. En grøn CI-kørsel viser softwarekontrol for den
konkrete commit; den siger ikke, at Pi'en kører den commit.

Testantal angives i den konkrete CI- eller pytest-rapport. Antallet kan falde,
når døde forsøgsprogrammer og deres tests fjernes. Det er vigtigere, at de
aftalte produktionsfunktioner og fejltilstande er dækket, end at bevare et
historisk stort testtal. Fjern ikke en relevant fejlet test for at få grønt.

Unit-testfixtures er ikke et uafhængigt datasæt til måling af modellens
detektionskvalitet. Ved en faglig sammenligning kræves adskilte og mærkede
trænings-/evalueringsforløb, tydelig analyseenhed og en beskrivelse af falske
positiver og begrænsninger. Sådanne tidligere forsøg er bevaret i Git-historien;
de er ikke længere driftspaneler eller runtimekommandoer i produktet.

Den virkelige installation verificeres særskilt efter [ACCEPTANCE.md](ACCEPTANCE.md).

## Lokal kontrol af den samlede version

Den 4. november 2026 bestod den samlede lokale kørsel **722 Python-tests** uden
udeladelser samt **9 JavaScript-tests** af navigationen. Ruff lint/formatering,
Python-/shell-/JavaScript-syntaks og bygning af produktionspakken bestod også.
Wheel-indholdet blev kontrolleret for fravær af de fjernede forsøgsmoduler,
historiske benchmarkdata og træningsdatasæt.

Den samlede integrationstest bruger en faktisk gemt og genindlæst SSH-model,
regler for SSH/preauth/UFW/sudo, den fælles SQLite/outbox, readonly-dashboard og
en lokal erstatning for Discord. Den kontrollerer genstart/genlæsning uden
dobbelte alarmforløb eller leveringskvitteringer samt uændrede modelbytes og
tærskel. Opgraderings-/installationstests simulerer systemd og servicekonti;
de erstatter ikke den konkrete Pi-accept.
