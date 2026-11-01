# Sprint 2 · Discord alarmnotifikationer

Notifieren er en separat systemd-tjeneste med sin egen systembruger.
Den læser kun SQLite i read-only-tilstand og behøver hverken adgang til
systemjournalen eller collectorens skriverettigheder. Webhooken ligger kun på
Pi'en i en privat fil, ikke i `config.toml` eller Git.

## Forudsætning

Opret en privat Discord-kanal og en webhook under kanalens integrationer.
Webhook-URL er en hemmelighed. Del den aldrig i terminaloutput, screenshots,
GitHub issues eller chat. Notifieren sender som standard kun alarmtitel,
alvorlighed og tidspunkt — ikke IP-adresser eller rå logs.

## Installation på Pi (efter bestået CI og kontrolleret kildeopdatering)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin yggdrasil-notifier
sudo usermod -aG yggdrasil-data yggdrasil-notifier
sudo install -d -o root -g root -m 0700 /etc/yggdrasil-ids/notifier-secret-input
```

Skriv webhook-URL manuelt via `sudoedit` til
`/etc/yggdrasil-ids/discord-webhook.url` (ingen kommandoargumenter med hemmeligheder).
Sæt ejerskab og adgang:

```bash
sudo chown root:yggdrasil-notifier /etc/yggdrasil-ids/discord-webhook.url
sudo chmod 0640 /etc/yggdrasil-ids/discord-webhook.url
sudo install -o root -g root -m 0644 deploy/yggdrasil-notifier.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/yggdrasil-notifier.service
sudo systemctl enable --now yggdrasil-notifier.service
```

Vent til notifieren har initialiseret sit private checkpoint, så ældre alarmer
ikke bliver sendt som nye. Kør en testbesked med `--test` separat (samme
webhook og konfiguration), og kontrollér i Discord.

```bash
sudo -u yggdrasil-notifier /opt/yggdrasil-ids/venv/bin/yggdrasil-ids notify \
  --config /etc/yggdrasil-ids/config.toml \
  --webhook-file /etc/yggdrasil-ids/discord-webhook.url \
  --state-file /var/lib/yggdrasil-notifier/state.json --test
```

Systemet forsøger ikke at genafspille gamle alarmer. En Discord-netværksfejl
stopper ikke collectoren. På grund af et muligt crash efter kvittering, men før
checkpoint, kan en notifikation i sjældne tilfælde leveres to gange.
