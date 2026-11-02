# Sprint 4 – Pi-runbook uden produktionsændringer

**Mål:** Opbygge reproducerbar ML-evidens til eksamensrapporten. Følg kun denne procedure på den private Yggdrasil Pi, og kør den som den almindelige bruger vidar. Begge trin kan gentages med en ny privat labmappe; ingen produktionsmodel trænes eller aktiveres.

## Inden start

- Sprint 3 er funktionelt afsluttet på Pi. Samtlige tre systemd-services skal fortsat være aktive.
- Sprint 4-branchen er `sprint-4/ml-evaluation`, baseret på den verificerede Sprint 3-branch. **Den er ikke installeret på Pi og skal ikke installeres som ny wheel for denne test.**
- Tag versions-SHA fra seneste grønne GitHub CI-kørsel på Sprint 4; `git show` henter kun scriptet fra netop denne commit.
- Der publiceres ikke private SQLite-filer, SSH-journalposter, screenshots, normalprofiler, modelartefakter eller IP-adresser på GitHub.

## Trin A – læs kun SSH-observationernes kvalitet

Erstat `INDSAET_FULD_CI_BESTAAET_SHA` med den godkendte 40-tegns-commit. Denne kode ændrer intet og udskriver kun aggregerede tællinger.

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  git fetch --no-tags origin sprint-4/ml-evaluation
  sha='INDSAET_FULD_CI_BESTAAET_SHA'
  test "$(git rev-parse origin/sprint-4/ml-evaluation)" = "$sha"
  git show "$sha:deploy/sprint4_ml_readiness.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python - \
      --config /etc/yggdrasil-ids/config.toml
)
```

Gem output privat som bilag ML-A. Et tal over 80 er **ikke** automatisk en tilladelse til at træne live-modellen. Audit udskriver altid `production_training_authorized=false`, fordi den ikke kan bedømme, om loginforsøgene er legitim normaltrafik.

## Trin B – træn og verificér modellen på syntetiske SSH-scenarier

Scriptet opretter automatisk en **ny privat mappe** under vidars hjemmemappe, genbruger den installerede yggdrasil-ids CLI til syntetisk laboratorium og kontrollerer hold-out-rapporter med en pinned verifikator. Det stopper ingen systemd-service, ændrer ingen firewall og overskriver ikke produktionsmodellen.

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  git fetch --no-tags origin sprint-4/ml-evaluation
  sha='INDSAET_FULD_CI_BESTAAET_SHA'
  test "$(git rev-parse origin/sprint-4/ml-evaluation)" = "$sha"
  script_file="$(mktemp)"
  trap 'rm -f "$script_file"' EXIT
  git show "$sha:deploy/sprint4_run_synthetic_lab.sh" > "$script_file"
  bash -n "$script_file"
  bash "$script_file" "$sha"
)
```

**Forventet resultat:** PASS for 3 aktive IDS-services før og efter; en lokal labmodel med mindst 80 træningsrækker; separate train/validation/test; output med TP, FP, TN, FN og korrekt genberegnet precision, recall og false-positive-rate. Den endelige modelversion og de præcise resultater læses fra terminaloutput og den nye lab-rapport. En historisk test har 312/44/41 hændelser, men den nye generering afhænger af tidspunktet.

**Gem fra `LAB_DIR`, som scriptet selv udskriver:** report.md, report.json, SHA-256 for rapport og lab-model.json. Sidstnævnte er kun en syntetisk artefakt og må aldrig kopieres til `/var/lib/yggdrasil-ids/model.json`. Del ikke hele mappen offentligt.

## Trin C – eksamensbeviser

- **ML-A:** Read-only produktionsaudit (event/featuretælling, modelstatus, begrænsning).
- **ML-B:** `report.md` og verifikators aggregerede evalueringsoutput fra isoleret lab, tydeligt mærket **syntetisk**.
- **ML-C:** Dokumentation for adskilt trænings-, validerings- og testgrundlag; SHA-256 og algoritmebeskrivelse.
- **ML-D:** Bestående unit tests og CI på Python 3.11 og 3.13.
- **ML-E:** Diskussionsafsnit: ægte Pi har én primær SSH-bruger og få data; mere aktivitet i virksomhed er ikke nødvendigvis bedre repræsentativ normalprofil.

## Hvis et trin fejler

Genstart ikke collector eller modificér modelstien. Send kun de aggregerede terminalresultater og eventuelle fejlmeddelelser (fjern private stier/adresser hvis de forekommer). Laboratoriemappen bevares privat til inspektion. Der er ingen automatisk rollback af produktionssystemet, fordi denne procedure slet ikke ændrer det.

## Ekstra mulighed – senere ægte live-model

En produktionsmodel skal først trænes efter særskilt gennemgang af normaltrafik, tilstrækkelig variation, bevidst opdeling af datasæt og accept af modelartefakt. Start ikke træning eller restart ud fra tallet 80 alene. Anvend programmets eksisterende `export-features` og `train` med en godkendt afgrænset periode, hvis disse krav opfyldes. Ellers dokumentér ærligt en trænet laboratoriemodel og en endnu ikke trænet produktionsmodel.
