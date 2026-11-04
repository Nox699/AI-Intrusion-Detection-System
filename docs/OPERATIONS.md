# Drift

Installationen beskrives i [deploy/INSTALL_PI.md](../deploy/INSTALL_PI.md).
Denne vejledning gælder den samlede produktionsrelease, ikke de tidligere
trinvise sprint-installationer.

## Tjenester og data

| Del | Funktion |
| --- | --- |
| `yggdrasil-collector.service` | Løbende SSH/preauth- og UFW-indsamling, regler og SSH-ML |
| `yggdrasil-web.service` | Loginbeskyttet dashboard på `127.0.0.1:8765` |
| `yggdrasil-notifier.service` | Levering af nye alarmforløb til Discord |
| `yggdrasil-sudo.timer` | Starter sudo-jobbet omtrent én gang i minuttet |
| `yggdrasil-sudo.service` | Privat sudo-indsamling, regler, alarmoverførsel og anonym eksport |

De tre første services skal normalt være aktive. Sudo-servicen er et oneshot-
job og kan normalt stå som `inactive` mellem kørslerne; dens timer skal være
aktiv og aktiveret til opstart.

```bash
systemctl is-active yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
systemctl is-active yggdrasil-sudo.timer
systemctl is-enabled yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo.timer
systemctl list-timers --all yggdrasil-sudo.timer
```

De centrale filer er:

| Placering | Indhold |
| --- | --- |
| `/etc/yggdrasil-ids/config.toml` | Fælles konfiguration |
| `/etc/yggdrasil-ids/web-secrets.json` | Dashboardlogin og sessionsnøgle |
| `/var/lib/yggdrasil-ids/events.sqlite3` | Produktionshistorik, alarmer og outbox, schema5 |
| `/var/lib/yggdrasil-ids/model.json` | Privat SSH-model |
| `/var/lib/yggdrasil-sudo/sudo.sqlite3` | Privat normaliseret sudo-historik, schema2 |
| `/var/lib/yggdrasil-sudo-public` | Små anonyme sudo-eksporter til web |
| `/var/lib/yggdrasil-notifier/delivery.sqlite3` | Privat leveringshistorik og kildeidentitet |

SSH/UFW- og sudo-indsamling har forskellige journallæsere, men arbejder med den
samme produktionsalarmkø og det samme dashboard. Ingen sudo-model er nødvendig.

## Dashboard

Tilgå port 8765 gennem SSH-tunnelen i [README](../README.md).
Indsamling og alarmering fortsætter, når browseren lukkes.

| Side | Indhold |
| --- | --- |
| Oversigt | Aktivitet, alarmer og driftsoplysninger |
| SSH | Autentificeringer og tilhørende modelvurderinger |
| Preauth | Understøttede afbrydelser før autentificering og deres regelalarmer; holdes uden for loginfejlstatistik og ML |
| Netværk | Registreret UFW-aktivitet og mulige TCP-portscanninger |
| Sudo | Registrerede regelalarmer og seneste anonyme procesaktivitet |
| Alarmer | Alarmforløb med regel/model, tidspunkt og evidens |
| Machine learning | Den aktive SSH-model, træningsgrundlag, tærskel og løbende vurderinger |
| Systemstatus | SSH-model, collector, aktiveret portscanregel og frisk sudo-regelstatus |

En trekant i menuen angiver et nyt eller opdateret registreret alarmforløb fra
de sidste 24 timer. Åbn den relevante sektion for at markere dens aktuelle
forløb som set; åbn en alarm for at markere kun den. Alarmoversigten markerer de
aktuelle forløb på tværs af sektioner. Nye fund på et eksisterende forløb kan
vise trekanten igen. Markeringen er lokal for browser/origin og ændrer ikke
alarmhistorikken eller Discord-leveringen.

Sudo-listen viser højst 15 procesgrupper. Flere loglinjer kan høre til den samme
proces. Brugernavne og kommandolinjer indgår ikke i denne liste. En regelkandidat
fra før integrationsaktiveringen er ikke en ny registreret produktionsalarm.

## SSH-modellen

Den samlede driftskontrol skal kræve en indlæst og trænet SSH-model, der kan
udløse alarmer. `untrained` eller `error` må ikke præsenteres som et færdigt
regelsæt-plus-ML-produkt. Reglerne kan fortsætte ved en modelfejl, men fejlen
skal undersøges og være synlig i dashboardet.

En modelvurdering gælder en numerisk observation for én kilde i det valgte
tidsvindue. Højere score betyder mere afvigende; score er ikke sandsynlighed for
angreb. Sammenlign med den gemte tærskel og læs den konkrete evidens.

Modellen trænes ikke automatisk under drift. `train` er en eksplicit lokal
administrationshandling på et gennemgået normalt datasæt med provenance.
Ukendte succesfulde logins og planlagte fejl-/angrebsforsøg må ikke blot regnes
som normaltræning. Modellen skal matche featuredefinition, vindue og den
installerede scikit-learn-version. Genstart af collector aktiverer en bevidst
modeludskiftning; HTTP-forespørgsler kan ikke gøre det.

Opgraderingen af den kendte Yggdrasil-installation bevarer den validerede,
eksisterende models indhold og tærskel og aktiverer dens alarmering. Det
dokumenterer ikke en generel detektionsrate eller en lav falsk-positiv-rate.

## Fejl og friskhed

```bash
sudo journalctl --unit=yggdrasil-collector.service --lines=40 --no-pager
sudo journalctl --unit=yggdrasil-sudo.service --lines=40 --no-pager
sudo journalctl --unit=yggdrasil-web.service --lines=40 --no-pager
sudo journalctl --unit=yggdrasil-notifier.service --lines=40 --no-pager
```

Et aktivt systemd-job alene beviser ikke frisk journalindsamling. Kontroller
heartbeat, journalposition og sudo-checkpoint sammen med dashboardets status.
Sudo-integrationens checkpoint og slutmarkør må højst være 180 sekunder gamle.
Oversigts- og aktivitetseksporternes egen grænse er 300 sekunder. Manglende,
forældet eller ugyldigt input vises som utilgængeligt frem for nul aktivitet.
En frisk, tom periode kan derimod være normal stilstand.

Ved journalrotation, længere udfald eller større klokkespring kan der være
datamangler. Sudo-polling stopper ved et ikke-understøttet langt hul og kræver
gennemgået genoptagelse. Gentagne fejl løses ved kildekontrol og reparation,
ikke ved at nulstille historik eller sende flere testforsøg.

Manglende Discord-besked undersøges gennem outbox og notifierens
leveringsstatus. Start ikke en ekstra notifier ved siden af den eksisterende,
og nulstil ikke dens private database. En registreret alarm og et køjob er ikke
i sig selv et leveringsbevis. Udskriv aldrig webhookværdien som fejlsøgning.

## Detektionsgrænser

- SSH-modellen vurderer autentificeringsmønstre med seks features, ikke indholdet
  af en efterfølgende SSH-session. Et vellykket login kan stadig være skadeligt.
- Preauth-reglen dækker de understøttede OpenSSH-formater, ikke alle typer
  afbrudte eller mislykkede forbindelser.
- Portscanreglen ser kun de understøttede blokerede indgående TCP SYN-pakker,
  som UFW faktisk logger. UDP og andre scanningsformer dækkes ikke automatisk.
  Ratebegrænsning eller manglende logposter kan skjule et mønster.
- Sudo-reglerne finder autentificeringsfejl og sudoers-afvisninger. De vurderer
  ikke formålet med en tilladt kommando og fastslår ikke, at nogen fik højere
  rettigheder.

## Backup, opdatering og retention

Brug SQLite-backupfunktionen eller opgraderingsværktøjets konsistente backup;
kopiér ikke en aktiv database som en almindelig fil. Opgraderingen bevarer
aktuel SSH/UFW/sudo-historik, model, outbox-identitet og notifierens
leveringshistorik. Rollback må ikke overskrive ny produktionshistorik med en
ældre databasekopi. Se den konkrete fremgangsmåde i installationsvejledningen.

Retention og databasebudget sættes i konfigurationen. Sletning af gamle
alarmforløb må ikke genbruge en leveringsidentitet eller afvikle notifierens
egen historik. Undersøg diskforbrug og datakvalitet, hvis budgettet nås.
Private backups skal beskyttes som de oprindelige driftsdata.
