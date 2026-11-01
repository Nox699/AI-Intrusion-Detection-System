# Sprint 3 · Kontrolleret Pi-opgradering (plan, endnu ikke udført)

**Status:** Godkendt migration på **kopi**, ikke på driftsdatabasen.
Rul ikke Sprint 3 ud alene på grundlag af CI eller den første kopitest.
Driftsændringen kræver en særskilt operatørhandling efter read-only preflight.

## Hensigt og faste sikkerhedsgrænser

- Pi bliver på eksisterende Sprint 2-drift indtil kontrolleret stop.
- Hent og byg kun en entydig, CI-bestået commit på
  `sprint-3/network-monitoring`. Notér hele SHA; installér ikke tilfældig
  `origin/HEAD` eller arbejde med lokale, uafklarede ændringer.
- Ingen ændringer af SSH, UFW, Fail2ban, Tailscale, router eller offentlige porte.
- Bevar `/etc/yggdrasil-ids/config.toml` og øvrige secrets. Tilføj ikke
  `[network] enabled=true` under denne opgradering: den nye standard er
  `enabled=false`, også når sektionen mangler.
- Programopgradering til schema v4 og tilkobling af live UFW-collector er
  **to separate beslutninger**.
- Alle tre tjenester (collector, web og notifier) skal kontrolleres efter
  installation, så en ændret outbox eller en stale cursor ikke overses.

## A. Read-only kontrol før installation

Kør først dette på Pi og vurder output, uden at vise rå journaldata eller
passwords, webhook eller hele konfigurationsfilen:

```bash
(
  set -eu
  cd /home/vidar/AI-Intrusion-Detection-System
  printf "=== Git ===\n"
  git status --short
  git rev-parse HEAD
  git rev-parse origin/sprint-3/network-monitoring

  printf "=== Tjenester ===\n"
  systemctl is-active yggdrasil-collector.service \
    yggdrasil-web.service yggdrasil-notifier.service

  printf "=== Disk ===\n"
  df -h /var/lib/yggdrasil-ids /var/backups/yggdrasil-ids /opt/yggdrasil-ids
  sudo du -sh /var/lib/yggdrasil-ids /var/backups/yggdrasil-ids

  printf "=== Python og database ===\n"
  sudo /opt/yggdrasil-ids/venv/bin/python - <<'PY'
import importlib.metadata
import sqlite3
from pathlib import Path

print("Pythonpakke:", importlib.metadata.version("yggdrasil-ids"))
path = Path("/var/lib/yggdrasil-ids/events.sqlite3")
with sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True) as db:
    print("Driftsschema:", db.execute("PRAGMA user_version").fetchone()[0])
    print("SQLite quick_check:", db.execute("PRAGMA quick_check").fetchone()[0])
print("Database bytes:", path.stat().st_size)
PY
)
```

Stop, hvis tjenesterne ikke er som forventet, databaseintegriteten fejler,
der er lokale ændringer, eller den tilgængelige diskplads er utilstrækkelig.
Nuværende schema forventes at være **3**; bekræft faktisk før opgradering.

## A2. Sikker releaseforberedelse (ingen installation)

Hjælpescriptet `deploy/sprint3_prepare.sh` er lavet til den eksisterende
Pi-installation. Det køres som `vidar` med en **fuld, CI-verificeret commit-SHA**
som eneste argument. Det stopper ved lokale Git-ændringer, forskellig
remote-SHA, stoppede IDS-tjenester, ændret driftskonfiguration eller manglende
SQLite-v3-integritet. Det bygger en wheel fra den præcise kilde i et
**midlertidigt** build-venv og gemmer wheel, SHA og et arkiv af den faktisk
installerede `/opt/yggdrasil-ids/venv` i en root-beskyttet undermappe under
`/var/backups/yggdrasil-ids`.

Scriptet kan hente Python-buildafhængigheder fra pakkeregisteret i den
midlertidige build-venv. Det installerer **ikke** runtime-afhængigheder eller
ny kode i den kørende venv, stopper/genstarter ikke services, ændrer ingen
netværksregler og migrerer ikke databasen. Stagingartefakterne er private,
må ikke pushes til GitHub, og eksisterende release-mapper overskrives ikke.

**Kør kun en pinned scriptversion.** Efter `git fetch` kan man bruge:

```bash
cd /home/vidar/AI-Intrusion-Detection-System
set -o pipefail
sha="INDSAET_40_TEGNS_GROEN_CI_SHA"
git show "$sha:deploy/sprint3_prepare.sh" | bash -s -- "$sha"
```

Brug ikke et uverificeret SHA eller `curl | bash`. Tjek resultatet og
hashene, før der planlægges en installation. Den nye wheel og snapshot af
tidligere venv er ikke i sig selv en gendannelsestest. **Den gamle v3-database
skal også sikres** efter tjenestestop.

## B. Installationsrækkefølge, først efter godkendt preflight

1. Verificér den valgte kilde-SHA mod en grøn CI-kørsel; gennemfør
   forberedelsen i afsnit A2. Kontrollér at den forventede wheel og det
   root-beskyttede arkiv af **faktisk installeret venv** findes, med hashes,
   før tjenester stoppes.
2. Kontrollér at wheel og eksisterende låste dependencies fungerer med Pi's
   Python/ARM64. Ingen ukontrolleret online dependency-opgradering.
3. Notér tjenesterne og stop **kun**
   `yggdrasil-notifier.service`, `yggdrasil-web.service` og
   `yggdrasil-collector.service`. De kan kortvarigt ikke overvåge eller
   notificere; SSH/Tailscale og UFW må fortsætte normalt.
4. Efter stop: lav **frisk konsistent v3-backup**, verify `integrity_check`,
   schema v3 og filrettigheder. Bevar også den private notifier-leveringsstate,
   eksisterende konfiguration, secrets og model i root-beskyttet backup.
   Ændre ikke journalpositioner manuelt.
5. Installer den byggede wheel i eksisterende venv med
   `--no-deps --no-index`, men kun efter at kilde, wheel og rollbackartefakter
   er valideret. Brug ikke `pip install -U` til transitive dependencies.
6. Med collector stoppet: kør `yggdrasil-ids init` som
   `yggdrasil-worker` på den eksisterende konfiguration. Dette migrerer
   **driftsdatabasen** fra v3 til v4 og opdaterer collector-state.
   Verificér integritet, bevaringskontrol og tomme nye netværkstabeller.
7. Start collector og web og verificér begge med rolleopdelt
   `doctor`, heartbeat, schema, SSH-historik og privat dashboard.
   Bekræft at `[network]` stadig er deaktiveret.
8. Start notifier og kontrollér leveringsstatus og at ingen tidligere alarm
   sendes som en ny notifikation. Gennemgå relevante systemd-fejl.
9. Først derefter: særskilt opt-in-måling med `network.enabled=true`,
   eksplicit tidsvindue og begrænset testtrafik fra en enhed, ejeren ejer.
   Vær opmærksom på UFW's rate limits og om pakkerne faktisk rammer Pi.
10. Dokumentér drift i mindst 24 timer samt performance, diskvækst,
    negative fejltests og genstart, inden ændringen accepteres fuldt.

## B2. Kontrolleret opgraderingsscript

Efter den beståede releaseforberedelse og grøn CI på scriptet kan `deploy/sprint3_upgrade.sh` anvendes
med en entydigt fastlåst (pinned) script-commit. Det installerer den allerede byggede wheel
fra `07fab99c88fe51a2cc455f51788bb17fd6c37fa4` og verificerer både dens SHA-256
og SHA-256 for arkivet af det tidligere installerede Python-miljø.

Scriptet kræver, at kildekode og afhængigheder er identiske mellem den byggede wheel og
den valgte script-commit. Det stopper derefter kun IDS notifier/web/collector og tager
en frisk offline-v3-SQLite-backup samt private kopier af data, Discord-state, secrets
og systemd-units. Først efter backupverifikation installeres den nye wheel uden online
dependency-opgraderinger, schema v4 migreres, eksisterende SSH/outbox-data verificeres,
og tjenesterne startes og helbredstestes én ad gangen.

**OBS: Dette er en reel driftsændring**. SSH og Tailscale påvirkes ikke tilsigtet,
men IDS-overvågning holder kortvarigt pause, mens de tre IDS-tjenester er stoppet.
Netværksindsamling forbliver deaktiveret (`network.enabled=false`), UFW på `low`.

```bash
cd /home/vidar/AI-Intrusion-Detection-System
git fetch origin sprint-3/network-monitoring
set -o pipefail
script_sha='INDSAET_40_TEGNS_GRONT_TESTET_SCRIPT_SHA'
git show "$script_sha:deploy/sprint3_upgrade.sh" | bash -s -- "$script_sha"
```

Scriptet afbryder ved fejl og udfører **ikke** automatisk rollback efter en migration.
En forkert restore kan slette nye hændelser. Bevar sikkerhedskopier og send
den sidste fejlfase til gennemgang inden videre arbejde.

## Fund under første produktionsopgraderingsforsøg

Det første forsøg nåede gennem frisk offline-backup, wheel-installation og
**root-baseret** kodeimport, men stoppede i fasen `migrating-db`, før
`yggdrasil-ids init` kunne køre som `yggdrasil-worker`:

```text
ModuleNotFoundError: No module named 'yggdrasil_ids.cli'
```

De tre IDS-tjenester var på dette tidspunkt stoppet. Den installerede pakke
var blevet udskiftet, men der foreligger **ikke** et verificeret
produktionsskema v4; schema skal kontrolleres read-only før yderligere
handling. Den friske v3-backup og arkivet af det tidligere fungerende
Python-miljø skal bevares.

Årsagen er nu **bekræftet** på Pi: Den installerede
`yggdrasil_ids`-pakkemappe var `0700`, og `cli.py` var `0600`.
Den originale wheel indeholdt faktisk `cli.py`.
Ved afgrænset reparation blev kun `yggdrasil_ids`-programkoden
sat til `0755` (mapper) og `0644` (filer); efterfølgende import som
alle tre servicekonti bestod. Database v3 med `quick_check=ok` blev
kontrolleret inden reparationen.

Ingen rettigheder blev lempet på `/etc/yggdrasil-ids` eller
`/var/lib/yggdrasil-ids`. Systemd-tjenesterne er ikke dokumenteret
genstartet endnu. Udfør kun en separat, kontrolleret migration og
driftskontrol fra den allerede installerede pakke; genkør ikke
det oprindelige fulde opgraderingsscript.

Deploy-scriptet blev derefter ændret til kun at bruge `umask 022` for
installation af kildekodefiler, og det kontrollerer fremover CLI-import
som **alle tre servicekonti før databaseskemamigration**. Den oprindelige
fejlramte kørsel skal **ikke genkøres direkte**. Fejlsøgning eller
kontrolleret tilbageførsel skal være gennemført først.

## C. Stop- og rollbackpolitik

- **Før migrationsskridt 6:** afbryd ved fejl, gendan den tidligere
  programversion og genstart de eksisterende tjenester, hvis de er stoppet.
- **Efter migration til v4:** den tidligere Sprint 2-programkode forventer
  schema v3. **Reinstallering af den tidligere wheel alene er ikke nok.**
  En kontrolleret tilbageførsel kræver stop af alle IDS-tjenester, den
  **friske v3-backup**, tidligere wheel/kilde og genskabt notifier-state.
  Det kan miste hændelser indsamlet siden backup. Udfør ikke automatisk
  restore uden menneskelig vurdering af datatab og root-rettigheder.
- Hvis en tjeneste fejler, eller journaladgang, SQLite-integritet,
  diskforbrug eller notifikationsstatus afviger, skal aktivering
  af `network.enabled=true` udskydes.

## Opnået evidens

[Pi-resultaterne fra 1. november 2026](SPRINT_3_PI_RESULTS.md)
dokumenterer konsistent v3-backup, vellykket v4-migration på kopi og
15 kernelposter/15 UFW-poster i ét fem-minuttersinterval. Det dokumenterer
ikke en sikker opgradering på driftsdatabasen eller dækningsgraden for en scanning.

## D. Genoptagelse efter rettighedsreparation (afventer på Pi)

**Forudsætning:** Kun den installerede kodepakke er repareret, og import af
`yggdrasil_ids.cli` som samtlige tre servicekonti er bestået. Da den
oprindelige opgraderingskørsel stoppede under `init`, skal der ikke tages
udgangspunkt i, at schema allerede er v4.

Den næste separate Pi-kontrol skal gennemføre følgende med
`network.enabled=false`: (1) alle tre IDS-tjenester er inaktive;
(2) frisk v3-backup fra fejlkørslen er `integrity_check=ok`;
(3) produktions-DB er stadig v3; (4) systemkonti kan eksekvere CLI;
(5) baseline for SSH-tabeller, outbox og Discord-instans gemmes
fra backuppen; (6) `yggdrasil-ids init` udføres én gang som worker;
(7) schema v4 og bevaringskontroller verificeres; (8) collector, web
og notifier startes ét ad gangen med målrettet kontrol.

Vigtigt: Ved fejl efter migrationspunktet må v3 ikke genindlæses
automatisk. Bevar backup og log, og beslut tilbageførsel ud fra
faktisk status og mulig tabt historik. `systemctl reset-failed`
må kun anvendes for IDS-collector, hvis den ellers er verificeret klar.
Tjek den private webside via SSH-tunnel efter genstart. Den separate
UFW-kernel-opt-in og portscanning må først aktiveres efter denne accept.

### Enkeltstående genoptagelse efter bekræftet chmod-reparation

Et script med navnet `deploy/sprint3_resume_after_permissions.sh` er
udelukkende til den dokumenterede hændelse med root-installerede kodefiler
(mode `0700`/`0600`) og den specifikke offline-v3-backup
`sprint3-offline-Ga0vDrfK`. Scriptet geninstallerer **ikke** wheel.
Det kræver netop v3 på både backup og drift, inaktive IDS-services,
CLI-import som alle tre servicebrugere og ens rækker i SSH/outbox-tabellerne.

Det migrerer én gang til v4 som `yggdrasil-worker`, sammenligner de
oprindelige SSH-/Discord-rækker med backup, genstarter collector/web/notifier
separat og tester lokalt dashboard og rolleopdelt adgang. Fejl stopper,
uden automatiseret rollback. **Kør ikke igen efter en migration**, heller
ikke hvis senere serviceopstart fejler.

Kør kun efter grøn CI på det nye script og med bevidst operatørhandling.
`network.enabled=false` og UFW `low` fastholdes.

## E. Status efter sikker genoptagelse

Den afbrudte produktionsopgradering er nu afsluttet med en separat
genoptagelseskørsel efter rettighedsreparation. Den faktiske
produktionsdatabase er schema v4 med bevaret SSH-/Discord-historik.
Collector, privat webdashboard og notifier er alle aktive; notifier
rapporterede `pending=0, delivered=1`. Der blev **ikke** aktiveret
netværksindsamling; `network.enabled=false` indtil særskilt opt-in.

Der er dermed **ikke behov for at genkøre** hverken
`sprint3_upgrade.sh` eller
`sprint3_resume_after_permissions.sh`. Begge er historiske
migrationsprocedurer. Nye handlinger må udelukkende vedrøre
den særskilte opt-in-test og efterfølgende verifikation.
Se [Pi-resultater](SPRINT_3_PI_RESULTS.md).
