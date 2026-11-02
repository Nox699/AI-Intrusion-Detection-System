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

## Status på Pi – read-only eksport gennemført, godkendelse afventer

**2. november 2026:** Brugeren kørte den CI-verificerede eksport på commit `7cb1cd8355c652533bc1c94a0f5c493fcf3de316` via `git show`, og eksportscriptet rapporterede **17 samlede SSH-hændelser, 17 kandidater til normaltræning** og `reviewed_as_normal=false`. Kommandoen oprettede `$HOME/yggdrasil-ml-private/real-candidates.json` lokalt. **Intet er sendt til GitHub**, og produktionsmodel, collector, web, UFW og Discord blev ikke ændret.

17 vellykkede login er **ikke automatisk dokumentation for 17 legitime logins**. Den nødvendige næste handling er manuel identitetskontrol i den read-only SQLite-database: genkend brugernavn, kildeadresse, autentificeringsmetode og tidsperiode. Disse oplysninger skal ses på Pi lokalt, **ikke kopieres til et offentligt repo**. Kun brugeren kan godkende alle 17 som faktisk kendt, legitim adfærd; ellers skal eksperimentets normaltræningsdata udvælges på ny uden fremmede eller usikre observationer.

**Hvis brugeren godkender alle 17:** Den eksisterende preview reserverer fem af de 17 som en lille tidsmæssigt korreleret kontrol og anvender 12 som godkendt virkeligt supplement til de 312 syntetiske normale træningsrækker. Dette er **324 blandede træningsrækker** og fem ikke-uafhængige virkelige succes-observationer til forsigtig shadow-inspektion, ikke en måling af real-world precision/recall/falsk-positiv-rate. Det syntetiske hold-out-testsæt forbliver uden for træningen. **Der er endnu ingen ny træning udført eller model aktiveret.**

## Faktisk hybrid-preview på Raspberry Pi – 2. november 2026

**Bestået, men ikke installeret:** Ejer kørte `deploy/sprint4_hybrid_ml_preview.py` fra source SHA `acb6a67abdc929fb9aced11e17d1268a378be2cb` som `vidar` på Pi'en med godkendte normale SSH-successkandidater. Programmet oprettede en **privat hybrid-kandidatmodel** i `~/yggdrasil-ml-private/preview-v1/candidate-model.json`; separat privat evalueringsrapport i `preview-v1/preview.json`. Ingen produktionsmodel blev installeret eller aktiveret.

| Måling | Faktisk output |
| --- | ---: |
| Syntetiske normale træningsrækker | 312 |
| Godkendte rigtige Pi-rækker til træning | 12 |
| Rigtige hold-out-successrækker | 5 |
| Afvigelser i disse 5 rækker | 0 |
| Syntetisk sluttest – recall | 94,7 % |
| Syntetisk sluttest – falsk positiv-rate | 13,6 % |
| Modelversion | `ssh-if-7cc1f15288d0c73b` |
| `production_model_activated` | `false` |

**Forbehold:** `0/5` anomalier blandt rigtige succeser er ikke dokumentation for nul falske positiver: observationerne er få, deler kilde og kan være tidsmæssigt afhængige. Den syntetiske sluttest er stadig kun syntetisk. En ML-model med 312 syntetiske og 12 rigtige rækker er en *eksperimentel hybridmodel*, ikke en verificeret model for Pi'ens normalfordeling.

**Næste gate:** Revideret wheel med `ml.alert_mode='shadow'`, frisk backup af schema-v4-SQLite, notifier-state, systemd-unit, konfiguration og tidligere venv; verifikation af kandidatmodellens sklearn-version/fingerprint og rettigheder. Skift til shadow-mode **før** collector indlæser modellen. Bekræft, at rigtige SSH-hændelser lagrer modelscore, og at der ikke opstår `ssh.isolation_forest`-fund eller Discord-beskeder. Ingen upload af private modelartefakter eller logs til GitHub.


## Staged release: backup, installation og rollback

Den eksperimentelle hybridmodel er trænet privat på Pi og identificeret
som ssh-if-7cc1f15288d0c73b. Den anvender 312 syntetiske normale
rækker plus 12 godkendte reelle Pi-success-rækker. Fem andre succeser
er reserveret til en lille kontrol (0 afvigelser). Den syntetiske
sluttest gav 94,7 % recall og 13,6 % falsk-positiv-rate. Ingen af
disse tal validerer modellens pålidelighed mod rigtige angreb.

### Trin 3A – staging, ingen produktionsændringer

Kør som vidar og brug **fuld SHA fra seneste grønne GitHub-CI**:

~~~bash
(
  set -euo pipefail
  umask 077
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_GRON_SHA_HER'
  git fetch --no-tags origin sprint-4/live-ml-shadow
  test "$(git rev-parse origin/sprint-4/live-ml-shadow)" = "$sha"
  helper="$(mktemp)"
  trap 'rm -f "$helper"' EXIT
  git show "$sha:deploy/sprint4_shadow_prepare.sh" > "$helper"
  bash -n "$helper"
  bash "$helper" "$sha"
)
~~~

Dette script skal bestå kontroller af schema v4, UFW low, netværksgrænse
5, aktive tjenester, ændret kildekode siden graf-release, modelmetadata,
venv-afhængigheder, rolleopdelt doctor og adgang til journalen.
Den bygger en pinnet wheel, gemmer en root-only kopi af hybridmodellen
og laver en venv-backup under /var/backups/yggdrasil-ids.
**Den stopper ingen tjenester og installerer ikke modellen.**
Indsend kun de ikke-sensitive PASS/STOP-linjer ved fejl.

### Trin 3B – separat, kontrolleret shadow-deployment

**Udfør ikke uden gennemgået staging-output og separat godkendelse.**
Et særskilt deploy-script verificerer hash og stop/start-gates,
stopper kun IDS-collector/web/notifier og tager friske offline-backups
af schema-v4-databasen, IDS-data, notifier-state, konfiguration
og systemd-units. Ingen ændring af SSH, Tailscale, UFW eller sudoers.

Efter verificeret backup installeres en ny wheel. Den eksisterende
[ml]-sektion får atomisk tilføjet feltet alert_mode = "shadow", og
først derefter kopieres den private model til worker-kontoens modelsti
med mode 0600. Collector, web og notifier startes og verificeres
sekventielt. Websiden skal vise *Eksperimentel skyggemodel*;
nye SSH-hændelser scores, men Isolation Forest må ikke generere
alarmer eller Discord-beskeder. Almindelige SSH-/netværksregler
skal fortsat virke.

### Trin 3C – eksplicit rollback, hvis deployment fejler

Rollback-scriptet er en separat, manuelt kørt operation.
Det kræver den fulde versions-SHA og den **præcise**
OFFLINE_BACKUP-sti udskrevet ved deployment. Det validerer
hashes, gendanner tidligere venv og konfiguration og fjerner
kun den eksperimentelle model, hvis den stadig matcher den
godkendte kandidat. Det **gendanner ikke gammel produktions-SQLite
eller Discord-checkpoint**, så nye hændelser og leveringshistorik
ikke utilsigtet går tabt eller genafspilles.

### Rapport og privatliv

Denne model er en **eksperimentel shadow-model**, ikke en pålidelig
produktionsbenchmark. Oplys AI-delen som faktisk hybridtræning og
live-scoring, og beskriv tydeligt datagrundlagets begrænsninger.
Private modelartefakter, featurefiler, IP-adresser, rå logs,
credentials og backups forbliver på Pi og uploades ikke til GitHub.
