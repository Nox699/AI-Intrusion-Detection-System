# Sprint 5 – Sudo/administratoraktivitet: sikker datakilde og detektionsplan

**Status:** Read-only journalinventar og unit tests udviklet på GitHub. **Ikke installeret på Pi. Ingen sudo-detektor eller Discord-varsler aktive endnu.** Det er ikke en afsluttet Sprint 5-accept.

## Mål

Udvide Yggdrasil IDS med forklarlig overvågning af lokale administratorhandlinger: sudo-kommandoer, autentificeringsfejl og afviste sudo-forsøg. Vi registrerer **sikkerhedshændelser**, ikke automatisk ond hensigt. En sudo-kommando er ikke i sig selv en intrusion.

## Trin 1: bekæmp datagætteri med sikker, afgrænset live-audit

`deploy/sprint5_sudo_journal_audit.py` læser alene eksisterende journald via `journalctl --output=json`, som `yggdrasil-worker` allerede har autoriseret journaladgang til. Scriptet læser kun metadata fra `_COMM=sudo` og `_UID=0`; en forfalsket `SYSLOG_IDENTIFIER=sudo` er ikke nok. Det samler **kun antal**, fordelt på dag (UTC) og følgende grove kategorier:

| Kategori | Betydning |
| --- | --- |
| `command_invoked` | Sudo-invokation med registreret `COMMAND=...` |
| `pam_auth_failure` | PAM autentificeringsfejl for sudo |
| `incorrect_password` | Logmeddelelse om forkert sudo-adgangskode |
| `not_in_sudoers` | Afvist handling på grund af manglende sudo-rettigheder |
| `pam_session_opened` / `pam_session_closed` | PAM-session start/slut |
| `other_sudo` | Ukendt, men troværdigt sudo-format |

Der skrives **intet** til SQLite, sendes **ingen** Discord-besked og vises **ingen** brugeridentiteter, kommandoer, absolutte filstier eller journal-meddeleser. Audit sætter altid `production_sudo_detection_active=false`. Der er en øvre grænse på 50.000 journalposter. Den ændrer ikke UFW, SSH, Tailscale, systemd, sudoers eller sudo-konfiguration.

En nulmåling kan skyldes logformat, journalretention eller anden producentmetadata. Den beviser ikke, at sudo aldrig anvendes. Det skal vi vide, før vi påstår, at sensoren kan detektere bestemte hændelser.

## Trin 2: Regelbaseret analyse (afventer faktisk Pi-output)

Afgrænsede, konfigurerbare detektorer til **gentagne sudo-autentificeringsfejl** og **afvist sudo-brug** er de mest forklarlige startpunkter. Sudo-kommandoer med gyldige rettigheder registreres som normal administration og må ikke automatisk udløse medium/high-alarm. Cooldown og outbox skal følge den eksisterende grouping uden at sende en notifikation pr. PAM-session. Eventuel SQLite-migration skal bevare schema v4 og notifier-state, med frisk offline-backup og rollbackgate.

Parseren bør aldrig acceptere `SYSLOG_IDENTIFIER` alene som producentbevis og må ikke lagre hemmeligheder fra sudo `COMMAND=` argumenter. Før implementering fastslås, om `sudo` eller en anden journalproducent faktisk leverer disse felter på Debian 13.

## Trin 3: Acceptkriterier

1. CI med Ruff, pytest og wheel-build på Python 3.11/3.13.
2. Read-only Pi-inventar med hvilke journalmeddelelser der findes. **Ingen** rå logs uploades til GitHub.
3. Validerede tests af betroet producent, inputstørrelse, dubletter og korrekt behandling af hver dokumenteret meddelelsestype.
4. En afgrænset *autoriseret* sudo-test med klart forventet resultat og dokumenteret falsk-positiv-begrænsning; ingen `sudoers`-ændring nødvendig.
5. Hvis en live-service tilføjes: konsistent SQLite-backup, verificeret systemd-opstart, bevaring af SSH/UFW-detektorer og Discord-outbox, separat cooldown og privat dashboard-visning.

## Første Pi-kommando (kør først efter grøn CI og pinning af SHA)

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  git fetch --no-tags origin sprint-5/sudo-monitoring
  sha='INDSAET_CI_BESTAAET_FULD_SHA'
  test "$(git rev-parse origin/sprint-5/sudo-monitoring)" = "$sha"
  git show "$sha:deploy/sprint5_sudo_journal_audit.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python - \
      --since '2026-10-22 00:00:00'
)
```

**Sikkerhedsnote:** Kør kun som den eksisterende `yggdrasil-worker`, ikke som root. Outputtet må deles, fordi det kun indeholder aggregerede antal. Originale journald-data og sudo-kommandolinjer må forblive på Pi'en.

## Afgrænsning i eksamensopgaven

Sprint 4's Isolation Forest er kun trænet på syntetiske **SSH**-scenarier. En fremtidig sudo-detektor kan ikke kaldes ML-baseret, medmindre vi implementerer nye sudo-features og har repræsentativt, adskilt trænings- og testgrundlag. Sudo-alarmer skal derfor først være **regelbaserede**, med tydelig evidens.
