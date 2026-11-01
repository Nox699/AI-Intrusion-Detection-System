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

## B. Installationsrækkefølge, først efter godkendt preflight

1. Verificér den valgte kilde-SHA mod en grøn CI-kørsel; byg en wheel fra
   en ren, isoleret kildekopi på Pi. Opbevar den tidligere installerede wheel
   eller en lokalt reproducerbar kildekopi med låste dependencies.
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
