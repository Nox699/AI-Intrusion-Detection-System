# Bidrag til Yggdrasil IDS

Projektet udvikles i afgrænsede sprints. Lav en branch til en konkret ændring,
og hold pull requests små nok til, at både adfærd og tests kan gennemgås.
Beskriv større ændringer i en issue, før implementeringen begynder.

## Lokal opsætning

Brug Linux eller Ubuntu i WSL og Python 3.11 eller nyere. Fra repositoryets rod:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps --editable .
```

`requirements-dev.txt` inkluderer de fastlåste driftsafhængigheder i
`requirements.lock`. Ændr kun afhængigheder som en bevidst del af ændringen,
og kontrollér både installation og tests efter en opdatering.

## Arbejdsgang

1. Opret en branch fra den aktuelle `main`, fx `feature/discord-alerts` eller
   `fix/login-validation`.
2. Lav én afgrænset ændring. Tilføj en regressionstest ved fejlrettelser, og
   opdatér relevant dokumentation, hvis adfærd eller opsætning ændres.
3. Kør kontrollerne nedenfor. Ved ændringer i brugerfladen skal relevante
   handlinger også prøves i en browser, herunder smal skærm og tom historik.
4. Gennemgå `git diff` og `git status`. Commit kun de tilsigtede filer med en
   besked, der beskriver den faktiske ændring.
5. Åbn en pull request mod `main` med problem, ændring, afprøvning og eventuelle
   begrænsninger. Gennemgå resultatet af CI før sammenfletning.

```bash
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check src tests
.venv/bin/python -m pytest --junitxml=test-results/pytest.xml
.venv/bin/python -m build --wheel --no-isolation
```

Brug `.venv/bin/python -m ruff format src tests` til bevidst formatering, og
gennemgå diffen bagefter. CI udfører ovenstående kontroller på Ubuntu 24.04 med
Python 3.11 og 3.13. En vellykket CI-kørsel dokumenterer softwarekontrollerne;
den erstatter ikke afprøvning af journaladgang og drift på en konkret Pi.

## Testdata og fortrolige oplysninger

Brug syntetiske testdata med eksempeladresser og fiktive identiteter. Commit
ikke rigtige sikkerhedslogs, lokale databaser, adgangskoder, sessionsnøgler,
private nøgler, Discord-webhooks eller lokal driftskonfiguration. Kontrollér
også screenshots, testoutput og nye eksempelfiler før upload. `.gitignore`
erstatter ikke denne gennemgang.

Hold demonstration og testdata adskilt fra rigtig drift. Følg
[afprøvningen på Pi](docs/TEST_ON_PI.md), når ændringen skal prøves på serveren,
og udfør kun kontrollerede sikkerhedstests på udstyr, du har tilladelse til at teste.
