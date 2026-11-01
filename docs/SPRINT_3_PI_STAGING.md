# Sprint 3 · Første Pi-accept: sikker databaseprøve på kopi

**Status:** Forberedt, men **ikke udført på målmaskinen**. En bestået
GitHub-test er ikke en driftsaccept.

## Grænser

Denne prøve gør følgende: Henter udviklingsbranchen, laver en konsistent
SQLite-backup af den **stadig kørende** Sprint 2-installation, kopierer
backupen til et privat midlertidigt område, indlæser ny Python-kode som
den almindelige bruger og migrerer **kun denne kopi** fra skema v3 til v4.

Prøven **installerer ikke** noget i produktions-venv, stopper ingen
services, ændrer ingen netværksregler, åbner ingen porte og aktiverer
ikke netværksindsamling. UFW bliver på `low`.
Der kan stadig være følsomme journaluddrag i kopien: Den ligger i en
privat mappe, slettes til sidst og må aldrig uploades til GitHub.

## Procedure (på Yggdrasil, som `vidar`)

Kontrollér først, at Git-mappen ikke har lokale ændringer.
Brug **den præcise Git-SHA, som følger med en grønt testet Sprint 3-udgave**.
Kommandoerne nedenfor er en skabelon, ikke en automatisk installation:

```bash
(
  set -eu
  cd /home/vidar/AI-Intrusion-Detection-System
  # Stop i stedet for blot at udskrive en besked, hvis arbejdsområdet er ændret.
  if [ -n "$(git status --porcelain)" ]; then
    git status --short
    echo "STOP: Repo har lokale ændringer. Undersøg dem før fortsættelse." >&2
    exit 1
  fi
  git fetch origin sprint-3/network-monitoring

  expected_sha="REPLACE_WITH_TESTED_COMMIT"
  actual_sha=$(git rev-parse origin/sprint-3/network-monitoring)
  test "$actual_sha" = "$expected_sha"

  work=$(mktemp -d)
  trap 'rm -rf -- "$work"' EXIT
  mkdir -m 700 "$work/source"

  git archive "$expected_sha" | tar -xf - -C "$work/source"

  backup="/var/backups/yggdrasil-ids/pre-sprint3-$(date +%Y%m%d-%H%M%S).sqlite3"
  sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids backup \
    --config /etc/yggdrasil-ids/config.toml --output "$backup"
  sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" \
    "$backup" "$work/staging.sqlite3"

  PYTHONPATH="$work/source/src" /opt/yggdrasil-ids/venv/bin/python \
    - "$work/staging.sqlite3" <<'PY'
import sqlite3
import sys
from pathlib import Path
from yggdrasil_ids.storage import Repository

path = Path(sys.argv[1])
tables = ("records", "events", "observations", "alerts",
          "discord_outbox", "discord_outbox_meta", "state")
with sqlite3.connect(path) as db:
    version = db.execute("PRAGMA user_version").fetchone()[0]
    assert version == 3, f"Forventede schema v3, fik v{version}"
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    before = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
              for name in tables}
    instance = db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0]

Repository(path).initialize()  # KUN den midlertidige kopi.

with sqlite3.connect(path) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    after = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
             for name in tables}
    assert before == after, (before, after)
    assert db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0] == instance
    assert db.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM network_evidence").fetchone()[0] == 0

print("PASS: ægte databasebackup migreret på kopi, v3 -> v4")
print("PASS: integrity_check=ok, SSH/alarmer/outbox bevaret")
print("PASS: netværkstabeller er tomme før aktivering")
print("Kopiens oprindelige rækker:", before)
PY

  echo "Produktionsdatabasen og systemd-tjenesterne er uændrede."
  echo "Root-beskyttet backup: $backup"
)
```

Hvis `git status --short` viste ændringer: Undersøg dem, og fortsæt
ikke med senere installationsskridt uden at forstå dem. Ved enhver
fejl under kopimigrationen **må produktionen ikke opgraderes**.
Den konsistente sikkerhedsbackup bevares root-beskyttet under
`/var/backups/yggdrasil-ids`.

## Øvrig første kontrol

Efter en bestået kopimigration kontrolleres antal kernel- og
UFW-poster pr. fem minutter, uden at vise deres indhold:

```bash
printf "Kernelposter (5 min): "
sudo -u yggdrasil-worker journalctl --system _TRANSPORT=kernel \
  --since "5 minutes ago" --no-pager --output=cat --quiet | wc -l

printf "UFW-poster (5 min): "
sudo -u yggdrasil-worker journalctl --system _TRANSPORT=kernel \
  --since "5 minutes ago" --no-pager --output=cat --quiet \
  --grep '\[UFW ' | wc -l
```

En stor forskel viser, hvor mange irrelevante kernelposter den
kommende opt-in collector i øjeblikket må passere. Hvis antallet er
højt, vurderes kildefilter/performance **før** aktivering.

Først efter denne accept kan der planlægges en kontrolleret
installation med korrekt wheel, rollback og kort tjenestestop.
Den live `[network] enabled=true`-prøve er et særskilt skridt.
