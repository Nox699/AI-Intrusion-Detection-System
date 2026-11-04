# Adgang og sikkerhedsgrænser

Yggdrasil IDS er beregnet til en privat Linux-server. Dashboardet bindes til
loopback og tilgås gennem en SSH-tunnel. Installationen åbner ingen firewall-
porte, ændrer ikke sudoers eller SSH-politik og blokerer ikke adresser automatisk.

## Driftsroller

| Rolle | Adgang |
| --- | --- |
| `yggdrasil-worker` | Skriver produktionsdata og privat sudo-tilstand; læser journalen via `systemd-journal` |
| `yggdrasil-web` | Læser produktionsdatabasen og anonym sudo-eksport via `yggdrasil-data`; har ingen journalgruppe |
| `yggdrasil-notifier` | Læser outbox og skriver kun sin egen private leveringsdatabase; webhook leveres som systemd-credential |

Workerens primære gruppe er **`yggdrasil-data`**. Web og notifier har egne
primære grupper og den supplerende datagruppe. Journalgruppen giver bred
journaladgang, selv om programmet filtrerer sine kilder. Web skal ikke køres
som root eller få journaladgang for at løse en visningsfejl.

Kildekode og releasefiler ejes af root. Produktionshistorik og model ligger
under `/var/lib/yggdrasil-ids`; konfiguration og weblogin ligger under
`/etc/yggdrasil-ids`. Privat sudo-tilstand ligger i en worker-ejet `0700`-mappe
med `0600`-database. Den offentlige sudo-mappe er `0750`, og eksporter er `0640`
for worker/datagruppe. Web skal fortsat være afskåret fra den private mappe.

## Hvad programmet kontrollerer

SSH-parsere kræver journalens betroede `_UID=0` og en kendt OpenSSH-`_COMM`.
Et selvvalgt syslog-tag alene er utilstrækkeligt. Sudo kræver betroet
`_EXE=/usr/bin/sudo`; en tekst i en tilladt kommandolinje må ikke kunne
forklæde sig som en PAM-fejl. UFW-data kræver understøttede kernelposter.
Input, journalforespørgsler, lister og numeriske værdier er afgrænsede.

Dashboardet kræver login, validerer værtsnavne og beskytter relevante
sessionhandlinger mod CSRF. Logtekst vises som tekst. Grafbibliotek og andre
ressourcer leveres lokalt uden CDN eller analyseværktøjer. Læstmarkeringer i
browseren indeholder kun anonyme alarmreferencer og revisioner.

Modellens JSON-format undgår eksekverbar objektindlæsning. Fingerprint opdager
ændringer i indholdet; det er ikke en digital signatur eller dokumentation for,
at træningsdata var normale. Adgang til model, konfiguration og database skal
derfor fortsat begrænses.

## Private data og credentials

SSH-historik kan indeholde kildeadresser, brugernavne og originale journalfelter.
Backups og modelobservationer er også private driftsdata. De skal ikke uploades
til GitHub eller indgå ufiltreret i en offentlig eksamensrapport.

Sudo-eksport og produktionsalarm-evidens indeholder ingen rå journalposter,
kommandolinjer, boot-ID, UID/PID eller passwords. Den normaliserede private
sensor er stadig privat, selv om den ikke gemmer rå kommandoer.

Webhook-URL og dashboardets secrets må ikke vises i terminaldiagnostik eller
gemmes i Git. En passwordudskiftning roterer også sessionsnøglen; genstart web
for at aktivere ændringen. Notifierens leveringsdatabase og outbox-identitet
skal bevares ved opgradering; nulstilling kan medføre dubletter eller mistede
leveringer.

En angriber med root-kontrol kan ændre journalen og lokal historik. Løsningen
lover ikke manipulationssikker logning eller fuldstændig registrering af angreb.
