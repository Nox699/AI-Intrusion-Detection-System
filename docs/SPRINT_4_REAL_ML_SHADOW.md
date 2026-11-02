# Experiment: få Isolation Forest til at score rigtig SSH-trafik på Yggdrasil

**Status:** Udviklet på `sprint-4/live-ml-shadow` med unit tests. **Intet er installeret i produktion endnu**, og testdata eller nye modelartefakter må ikke uploades til det offentlige repo.

## Hvorfor gør vi dette?

Produktionens SSH-journal viste 19 succesfulde login-events fra én kilde fordelt over fem dage, men kun **to adfærdskombinationer, når time_sin/time_cos udelades**. Det er utilstrækkeligt til en repræsentativ normalprofil eller et pålideligt produktions-FPR-estimat. 80 næsten ens logins eller syntetiske angreb skal **ikke** blandes ind som 'normalitet'.

Vi kan alligevel komme videre med et **eksperimentelt bootstrappet normaldatasæt**: syntetiske *legitime* SSH-forløb fra den allerede verificerede `train.jsonl` og et lille sæt virkelige autentificeringer, som ejeren har gennemgået og genkendt som legitime. Tidligere test/attack-data forbliver helt uden for træningen.

Systemets eksisterende Isolation Forest kan score de seks per-source SSH-features på hver ny loginhændelse. Den nye `ml.alert_mode='shadow'` betyder, at den lagrer score, tærskel, modelversion og afvigelsesflag i SQLite og viser dem i Machine learning-dashboardet, men **aldrig** genererer ML-fund, alarmer eller Discord-beskeder. De eksisterende SSH-/UFW-regler fortsætter uændret.

## Trin 1 – eksportér kun rigtige *normal-kandidater* fra Pi

Brug den **CI-godkendte SHA** som leveres, når udviklingsbranchen er klar. Kør kommandoen som `vidar`, men læs SQLite gennem den eksisterende `yggdrasil-worker`. Ingen private IP'er, brugernavne, raw journalrecords eller credentials eksporteres; `real-candidates.json` indeholder **stadig private numeriske observationer og tider og skal blive lokalt**.

```bash
(
  set -euo pipefail
  umask 077
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_FULD_GRON_SHA'
  git fetch --no-tags origin sprint-4/live-ml-shadow
  test "$(git rev-parse origin/sprint-4/live-ml-shadow)" = "$sha"
  mkdir -p "$HOME/yggdrasil-ml-private"
  chmod 700 "$HOME/yggdrasil-ml-private"
  test ! -e "$HOME/yggdrasil-ml-private/real-candidates.json"
  git show "$sha:deploy/sprint4_real_ml_export.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python - > \
      "$HOME/yggdrasil-ml-private/real-candidates.json"
  /opt/yggdrasil-ids/venv/bin/python - <<'PY'
import json
from pathlib import Path
p = Path.home() / 'yggdrasil-ml-private/real-candidates.json'
data = json.loads(p.read_text())
print('PI_SSH_SUCCESS_CANDIDATES=', data['candidate_success_rows'])
print('PI_AUTH_EVENTS_TOTAL=', data['all_authentication_event_count'])
print('APPROVED_NORMAL=', data['reviewed_as_normal'])
print('PRIVATE_FILE_MODE=', oct(p.stat().st_mode & 0o777))
PY
)
```

**Kontrol før videre:** Brugeren skal vide, at de inkluderede succesfulde SSH-logins faktisk tilhører egen normalaktivitet. En succes fra en ukendt kilde skal **ikke** godkendes som normal. De 19 journallogins og de 15 SQLite-events kan overlappe. Kun SQLite'ens egne `untrained`-observationer er kandidater i denne eksport.

## Trin 2 – træning i privat laboratorium, IKKE produktion

Når ejeren **udtrykkeligt** kan godkende de rigtige succes-observationer som normal, og filen er gennemgået, kan `deploy/sprint4_hybrid_ml_preview.py` køres via pinned `git show`. Den validerer lab-inputs med SHA-256 og separat facitliste, træner en model på de 312 syntetiske normale `train.jsonl`-observationer plus en del af de godkendte Pi-success-rækker og reserverer de sidste real-rækker som et *meget lille*, ikke-uafhængigt shadow-kontrolsæt. Den scorede synthetic test-split (41 hændelser) holdes helt ude af træning.

```bash
(
  set -euo pipefail
  umask 077
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_FULD_GRON_SHA'
  git fetch --no-tags origin sprint-4/live-ml-shadow
  test "$(git rev-parse origin/sprint-4/live-ml-shadow)" = "$sha"
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  git show "$sha:deploy/sprint4_hybrid_ml_preview.py" > "$tmp"
  /opt/yggdrasil-ids/venv/bin/python "$tmp" \
    --lab-directory "$HOME/yggdrasil-ml-lab-1LpJjZNi" \
    --real-candidates "$HOME/yggdrasil-ml-private/real-candidates.json" \
    --output-directory "$HOME/yggdrasil-ml-private/preview-v1" \
    --approve-reviewed-successes
)
```

**Vigtigt:** `--approve-reviewed-successes` betyder, at ejeren selv har gennemgået normalitetsforudsætningen, **ikke** at en succesfuld autentificering altid er sikker. Fjern dette flag, hvis data ikke er godkendt; scriptet vil så stoppe uden at oprette model. `preview-v1` skal være en *ny*, ikke eksisterende mappe. Ved gentagne eksperimenter bruges et andet privat outputnavn.

Output er kun en eksperimentel kandidatmodel (`candidate-model.json`) og en aggregeret `preview.json`. De skal **aldrig** skubbes til GitHub eller kopieres direkte til `/var/lib/yggdrasil-ids/model.json`.

## Trin 3 – kun efter gennemgået preview: installér og aktivér shadow

**Ikke automatisk en del af trin 1 eller 2.** Vi skal først godkende den genererede preview-måling, verificere source-modellen og gennemføre en separat installationsprocedure med en ny offline SQLite-backup, eksisterende model/config backup og rollback. Denne procedure skal sikre, at den nye wheel er testet, og at `/etc/yggdrasil-ids/config.toml` får `[ml] alert_mode = 'shadow'` **før** modellen kan indlæses og den aktive collector genstartes. Vi må ikke eksponere et endpoint, åbne firewallporte, nulstille UFW eller flytte en syntetisk model ind som normal produktion uden gate.

Når det er gjort og verificeret, bør dashboardet på det rigtige **8765** vise `Eksperimentel skyggemodel`, og nye legitime SSH-hændelser skal stå som `scored` med score, tærskel og anomali-flag. **AI-alarmer og Discord er bevidst undertrykt**, indtil selvstændig real-world-validering retfærdiggør det. SSH-regler og deres Discord-alarmer fortsætter.

## Angrebssimuleringer og faglig måling

Simulerede mislykkede SSH-loginforsøg og username spraying hører til *test*, **aldrig normaltræning**. Før vi laver virkelige forsøg, kontrollerer vi key-/password-auth, firewall og Fail2ban og sikrer, at fjernadministration via Tailscale fortsat fungerer. Under skoleeksamen kan vi også replay'e dokumenterede syntetiske SSH-scenarier i et isoleret lab, mens den skyggebaserede model scorer rigtige normalhændelser uden at overdrive datagrundlaget.

**Afgrænsning:** Denne model er *eksperimentelt bootstrappet*, ikke valideret produktion. En høj score er ikke angrebssandsynlighed; synthetic-only precision/recall/FPR er ikke real-world metrics. 15 reelle success-events er stærkt begrænsede og tæt tidskorrelerede.
