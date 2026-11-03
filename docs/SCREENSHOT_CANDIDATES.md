# Screenshot-kandidater og evidensbank – Yggdrasil IDS

**Formål:** Gem mange originale billeder i privat projekt-/eksamensmappe,
men udvælg kun de stærkeste til den endelige rapport. Screenshot-kandidat
er **ikke** det samme som godkendt rapportbilag. Et screenshot af en
dry-run/fake notification må aldrig beskrives som en faktisk Discord-levering.

**Sikkerhed:** Gem uredigerede originaler lokalt med adgangskontrol. Lav
en særskilt sløret rapportkopi; fjern webhook-URL'er, credentials, rå
IP-adresser, private brugernavne, SSH-keys og følsomme journalbeskeder.
Undgå at sende rå billeder med hemmeligheder til GitHub. Screenshots er
ikke automatisk uploadet eller vurderet af ChatGPT.

## Sprint 5 – Sudo og privilege monitoring

| Kandidat | Visning | Status | Faglig værdi |
| --- | --- | --- | --- |
| S5-01 | Ubuntu-VM: tre kontrollerede sudo-auth-fejl, `pam_auth_failure=3`, `incorrect_password=3` | Terminalresultat verificeret; screenshot ikke gennemgået | Testmiljø og faktiske auth-fejl |
| S5-02 | Historisk sudo-replay: tre forskellige fejlede processer, `sudo.repeated_auth_failure=1` | Terminalresultat verificeret; screenshot ikke gennemgået | Positiv detektion med regelmotor |
| S5-03 | Live-shadow: `sudo.repeated_auth_failure=1`, 21 parsede poster, privat SQLite | Terminalresultat verificeret; screenshot ikke gennemgået | Realtidsdetektion under autoriseret test |
| **S5-04** | **To `sudo.repeated_auth_failure`-fund i VM'ens historiske preview** | **Bruger oplyser screenshot taget – fil/billedindhold ikke gennemgået** | To separate kontrollerede testserier |
| S5-05 | SQLite-outbox med `temporary_alert_rows=2`, `fake_notifier_deliveries=2` og `discord_messages_sent=0` | Terminalresultat verificeret; screenshotstatus ukendt | Automatisk outbox/notifier-test med falsk afsender |
| S5-06 | Dansk sudo-besked som redacted dry-run, `webhook_read=false` | Terminalresultat verificeret; screenshotstatus ukendt | Notifikationsformat, ikke Discord-levering |
| **S5-07** | **En rigtig Discord-besked mærket SUDO LABTEST fra Yggdrasil** | **Levering og systemd SUCCESS bekræftet af bruger; screenshot ikke taget ved første forsøg** | Reelt Discord-ack af *syntetisk* sudo-alarm i privat test-outbox – ikke automatisk registreret sudo-angreb |
| S5-08 | Isoleret sudo SQLite-checkpoint/replay: 402 unikke poster og 0 ekstra ved tredje replay | Terminalresultat verificeret; screenshotstatus ukendt | Deduplikering/genoptagelse på historiske journaldata |
| S5-09 | Pi baseline: 411 sudo-journalposter med nødvendige metadata, 0 PAM-fejl; tre IDS-tjenester aktive | Terminalresultat verificeret 3. november; screenshotstatus ukendt | Normal journaladgang før installation |
| **S5-10** | **To separate sudo-shadow-polls på Pi; `second_poll` med `previous_checkpoint_present=true`, `journal_rows_read=3`, `new_normalized_sudo_rows=0`, `overlap_duplicates_skipped=3`** | **Praktisk terminaltest bestået 3. november; screenshot-kandidat, fil endnu ikke gennemgået** | Beviser normal logindlæsning, checkpoint og deduplikering på Pi uden alarm |
| **S5-11** | **Manuel sudo-shadow systemd-oneshot: `Result=success`, `ExecMainStatus=0`, 54 journalposter, 0 alarmkandidater og `discord_alerts_sent=0`** | **Praktisk test bestået; screenshot-kandidat, fil endnu ikke gennemgået; timer stadig `inactive`** | Dokumenterer rigtig sudo-sensor under systemd uden uønskede alarmer |
| **S5-12** | **Aktiveret sudo-shadow-timer: `active`/`enabled`, seneste systemd-`success`, 69 private SQLite-rækker, 0 sudo-kandidater og checkpoint 10:51:33 CET** | **Terminalmålinger verificeret 3. november; screenshot-kandidat, billedfil endnu ikke gennemgået** | Dokumenterer periodisk systemd-shadow-overvågning uden sudo→Discord-alarmer |

## Andre sprint-kandidater

| Kandidat | Visning | Status |
| --- | --- | --- |
| S1-01 | SSH-regler og loginhændelser i dashboard | Historiske demonstrationer; udvæl senere |
| S2-01 | Automatisk SSH-preauth-alarm og Discord-desktopnotifikation | Praktisk demonstreret tidligere; find original lokalt |
| S3-01 | UFW-TCP-portscan-regel, alarm og leveret Discord-besked | Praktisk demonstreret tidligere; find original lokalt |
| S3-02 | Privat netværksdashboard og grafer | Praktisk demonstreret tidligere; find original lokalt |
| S4-01 | Syntetisk Isolation Forest-demo, træningsgrundlag og modelstatus | Browserbillede omtalt i projektdokumentation; find original lokalt |
| S4-02 | Produktions-SSH-ML i shadow: score, tærskel og ingen alarm | Kan vises i dashboard; screenshotstatus ukendt |
| S4-03 | ML-versus-regler, confusion matrices og false positives fra hold-out-test | Reproducerbart laboratorieresultat; screenshotstatus ukendt |

## Udvælgelse til eksamensrapport

Vælg typisk ét billede pr. fagligt **forskellig** påstand:
real SSH/netværksdetektion, ML-evaluering og en sudo-alarm
kan være mere værdifulde end flere næsten identiske JSON-billeder.
Brug eventuelt et bilag som ekstra dokumentation, hvis
rapportens plads er begrænset.

**Tjekliste pr. kandidat:** Dato, miljø (Pi/VM/demo),
Git-commit, testmetode, præcis forventning og observation,
eventuelle udeladelser/sløringer og om billedet viser
en *rigtig* levering, en dry-run eller kun en regelkandidat.
Registrér først et billede som 'gennemgået', når filen
faktisk er blevet åbnet og kontrolleret.
