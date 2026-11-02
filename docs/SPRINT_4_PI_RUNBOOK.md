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

## Valgfrit trin B2 – trænet model synlig i separat dashboard

Vi har også en **syntetisk dashboard-demonstration**, hvor modellen vises som trained/ready, mens Pi'ens rigtige dashboard fortsat er untrained og uændret. Den bruger en ny privat demomappe og **kun loopback-port 8766**. Dette er især nyttigt til en tydeligt LAB-mærket eksamensillustration.

På Pi som vidar (ikke root):

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  git fetch --no-tags origin sprint-4/ml-evaluation
  sha='INDSAET_FULD_CI_BESTAAET_SHA'
  test "$(git rev-parse origin/sprint-4/ml-evaluation)" = "$sha"
  script_file="$(mktemp)"
  trap 'rm -f "$script_file"' EXIT
  git show "$sha:deploy/sprint4_ml_demo_dashboard.sh" > "$script_file"
  bash -n "$script_file"
  bash "$script_file" "$sha"
)
```

Den proces bliver stående i Pi-terminalen, indtil den afsluttes med Ctrl+C. Fra laptoppen oprettes en **separat** SSH-tunnel:

```bash
ssh -N -L 8766:127.0.0.1:8766 homelab
```

Åbn **http://127.0.0.1:8766** (brug 127.0.0.1 frem for localhost for at holde democookien adskilt fra produktionsdashboardet). Demoens offentligt kendte *LAB-adgangskode* er `demo-yggdrasil`. Dette login må ikke benyttes til nogen live-IDS.

Kontrollér at siden eksplicit angiver demonstration, at **Model klar** vises, og at SSH-scorede observationer er til stede. Gem et screenshot mærket **ML-demo – syntetiske data**, ikke som en model trænet på Yggdrasil-produktion. Kør ikke webserveren på `0.0.0.0`, og åbn ikke firewallporte.

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

## Verificeret Pi-kørsel – 2. november 2026

**Trin A og B bestået** med den godkendte kildecommit `c3c9def02eba51e05c8ecd9902462c1a9a22d887`. Produktionsaudit: 15 SSH-events/observationer, 15 succesfulde logins, ingen fejl, én kilde, tre dage, 15 featurevektorer; minimum 80 og ingen live-modelfil. Syntetisk model: `ssh-if-16ae0fc3a05948df`, 312/44/41 split; evaluering og hashkontrol bestod. Collector, web og notifier var aktive før og efter. Alle artifacts er private på Pi.

**Trin B2 er nu gennemført og verificeret i browseren** med screenshot `ML-C1` af en separat syntetisk model som `Model indlæst` (312 træningsobservationer). Et supplerende screenshot `ML-C2` af de scorede hændelser afventer. Den oprindelige instruktion for B2 var: start den eksisterende, CI-godkendte demo på **127.0.0.1:8766**, ikke på port 8765. Gem screenshot privat og mærk det syntetisk. Ingen geninstallation af applikationen er nødvendig.

Se [Pi-resultatdokument](SPRINT_4_PI_RESULTS.md) for den faktiske matrix samt usikkerheder.

## Demovisning: Portforveksling konstateret og afklaret

**2. november 2026:** `sprint4_ml_demo_dashboard.sh` bekræftede, at
en syntetisk model stod som `ready` i den separate demodatabase,
41 SSH-hændelser havde status `scored`, og Gunicorn lyttede på
`127.0.0.1:8766`. Brugeren viste efterfølgende en browserside
med `Model ikke trænet` og autentiske SSH-observationer.
Det er derfor **den almindelige produktionsside på port 8765** –
ikke den nye demo på 8766. Produktionsstatus er korrekt.

**Åbn i stedet en særskilt tunnel på laptoppen:**

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8766:127.0.0.1:8766 homelab
```

**Besøg kun `http://127.0.0.1:8766/model` for LAB-demoen.**
Benyt demoens offentlige laboratorielogin. På 8765 vises stadig
den ikke-trænede produktionsmodel. Det er tilsigtet.

Det oprindelige demo-subkommando-output indeholdt standard-URL'en
`127.0.0.1:8765`, selvom wrapperen bagefter ændrede config til
port 8766. Det var misvisende. Wrapperen er nu ændret til
kun at vise den **faktiske 8766-URL**. **Genstart ikke det
allerede fungerende demo-script alene for at få den tekstændring.**

Screenshotet viser en privat Tailnet-adresse. Behold originalen privat,
og slør identiteten ved eventuel deling i eksamensopgaven.

## Status efter browseraccept

**02.11.2026:** Ejerens screenshot fra den separate syntetiske `8766/model`-visning viste `Model indlæst`, 312 træningsobservationer, alarmgrænse 0,615 og modelversion `ssh-if-bc574f0291c96358`. Dette er **en anden labtræning** end den særskilt verificerede hold-out-evaluering `ssh-if-16ae0fc3a05948df`.

Gem `ML-C1` privat; publicér ikke billedet automatisk på GitHub. Tag gerne `ML-C2` af *Seneste modelvurderinger*, så eksempler på afvigelsesscore og normal vurdering er dokumenteret. Den aktive produktionsmodel på 8765 er fortsat `untrained`; der er ingen plan om at erstatte den med syntetiske træningsdata.
