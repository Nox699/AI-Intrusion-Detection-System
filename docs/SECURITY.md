# Adgang og sikkerhedsgrænser

Sprint 1 er beregnet til en privat Linux-server. Webserveren bindes til loopback
og tilgås gennem en SSH-tunnel over den eksisterende Tailscale-forbindelse.
Den åbner ingen firewallporte og udfører ingen automatisk IP-blokering.

## Rettigheder

- `yggdrasil-worker` ejer data og kan læse systemjournalen gennem `systemd-journal`.
  Gruppen giver bred læseadgang til journalen, selv om collectoren filtrerer SSH.
- `yggdrasil-web` læser databasen gennem `yggdrasil-data` og får ikke journalgruppen.
- Program og virtuelt miljø ligger under `/opt/yggdrasil-ids/venv`.
- Konfiguration og loginoplysninger er `/etc/yggdrasil-ids/config.toml` og
  `/etc/yggdrasil-ids/web-secrets.json`.
- Database og eventuel model er `/var/lib/yggdrasil-ids/events.sqlite3` og
  `/var/lib/yggdrasil-ids/model.json`.

Bevar de rettigheder, installationsvejledningen angiver. Loginoplysninger og
virkelige logs skal ikke med i Git. En ændret adgangskode roterer sessionsnøglen;
genstart webprocessen for at aktivere ændringen.

## Hvad kontrollerne beskytter

Parseren kræver journalens `_UID=0` og en kendt `_COMM`. Et selvvalgt
`SYSLOG_IDENTIFIER=sshd` er utilstrækkeligt. Dashboardet kræver login, validerer
værtsnavne, beskytter login/logout mod CSRF og viser logtekst som tekst. Plotly og
andre ressourcer leveres lokalt uden CDN eller analyseværktøjer.

Modellens JSON-format undgår eksekverbar objektindlæsning. Fingeraftrykket opdager
ændringer, men er ikke en digital signatur. Skriveadgang til model, konfiguration
eller database skal derfor fortsat begrænses.

En angriber med root-kontrol kan ændre logs og lokal historik. Løsningen lover
ikke manipulationssikker dokumentation eller fuld registrering af alle angreb.
Brugeridentiteter og IP-adresser i historik og backups er følsomme driftsdata.
Den syntetiske demo og dens kendte adgangskode må kun bruges som demonstration.
