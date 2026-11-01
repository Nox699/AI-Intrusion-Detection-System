# Sprint 3 – Controlled TCP scan acceptance

**Status:** Planned, not run on Pi. On 1 November 2026 the first UFW journal opt-in
succeeded, with one stored firewall event and no scan alarms. UFW remains low.

The detector requires at least six **distinct incoming blocked TCP SYN destination
ports** in 60 seconds, grouped by source/destination/interface/sensor boot.
A logged packet is not proof of an attack.

## Preparation on Pi (read-only)

~~~bash
systemctl is-active yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
sudo ufw status verbose
ip -4 -o addr show dev wlan0 scope global
sudo ss -lnt '( sport >= :45010 and sport <= :45019 )'
~~~

Confirm that all ten test ports 45010-45019 are not listening and are not
allowed by a custom UFW rule. Use the **current private wlan0 LAN address**,
not a cached address. Do not change UFW, open ports, or scan public addresses.
Keep an SSH session connected.

Use the pinned read-only aggregate checker **before and after** the test:

~~~bash
cd /home/vidar/AI-Intrusion-Detection-System
sha="REPLACE_WITH_GREEN_CI_COMMIT"
git show "$sha:deploy/sprint3_network_observe.py" |
  sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python -
~~~

The checker uses SQLite mode=ro and prints **no IPs or raw logs**. It reports
logged UFW packets, blocked SYNs, selected test ports, the greatest number
of distinct ports in a rolling 60-second window for one source/destination
group, scan alerts, network evidence and Discord outbox entries.

## One bounded test from your own LAN laptop or Kali machine

If Nmap is available, scan ONLY the Pi's verified private LAN address.
Use the following as **one command line** in Windows PowerShell:

~~~text
nmap -sT -Pn -n --scan-delay 2s --max-retries 0 --host-timeout 90s -p 45010-45019 PI_LAN_IP
~~~

This is a low-rate, 10-port TCP connect scan with no NSE scripts,
version detection or broad network range. Do **not** run it from the
Pi itself or use a Tailscale destination in this first LAN test.
The traffic must reach UFW on the Pi. Private routing and prior
filtering can prevent it.

With UFW low, logging is rate-limited. Therefore, if the scan does not
create an alert, inspect **registered distinct blocked SYN ports** before
concluding the detector is broken.

## Verification after the scan

Within ten minutes, rerun the aggregate checker on Pi and open the
authenticated private dashboard at /network and /alerts.

The key output fields are:
- selected_port_packets_in_window: packet records on the test ports
- max_distinct_selected_ports_in_60s_one_group: scan rule evidence
- scan_alerts_in_window: local incident created
- network_evidence_in_window: incident evidence persisted
- scan_outbox_in_window: Discord notification queued
- collector_state, collector_heartbeat_age_seconds and error flags: health

Separately check notifier state:

~~~bash
sudo /opt/yggdrasil-ids/venv/bin/yggdrasil-ids notify \
  --config /etc/yggdrasil-ids/config.toml \
  --state-file /var/lib/yggdrasil-notifier/delivery.sqlite3 --status
~~~

After notifier polling, compare delivered count to the previous baseline and
visually confirm the message in the private Discord channel. One outbox record
is not evidence of a delivered Discord message. No alert is not evidence that
no scan occurred: check LAN path and rate limits first. Do not immediately
raise UFW to high/full, repeat many scans or change SSH/Tailscale settings.

Store only privacy-safe aggregates and screenshots (redact sensitive data)
in the public repository. This test is limited to authorized traffic on
the owner's own host and covers only this one TCP SYN rule, not all scans.

References:
https://manpages.debian.org/trixie/ufw/ufw.8.en.html
https://nmap.org/book/man-performance.html

## Første gennemførte scanning: registrering uden alarm

Nmap 7.94SVN scannede 10 private TCP-porte på egen Pi
den 2. november 2026 kl. 00:10 CET (alle `filtered`).
Read-only databasekontrol over 60 minutter viste
8 blokerede TCP SYN-poster til testportintervallet i **én**
kilde-/sensorgruppe, men højst **5** forskellige porte inden for
60 sekunder. Tærsklen er 6, og resultatet var derfor
0 scanalarmer, 0 netværksevidens og 0 nye scan-outboxposter.
Notifieren var konsistent med `pending=0`, `delivered=1`.
Collector var `running` uden registrerede analysefejl.

Denne test bekræfter reel modtagelse af scanrelateret
firewalltrafik, men **ikke** ende-til-ende-alarmlevering.
UFW `low` kan ratebegrænse; aggregater alene er ikke bevis
for årsagen til de manglende unikke porte.

**Næste diagnostik:** Read-only SQL-optælling pr. destinationsport
i testintervallet og kontrol af præcist logvindue. Først efter
denne gennemgang vælges en eventuel ny kontrolleret test.
Undgå en automatisk omlægning til `medium` som løsning:
også `medium` er ratebegrænset. Ændr ikke firewallregler,
tærskel eller loggerens niveau for at få en kunstig bestået test.
