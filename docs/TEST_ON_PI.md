# Accepttest på Raspberry Pi

**Status: Accepttesten på målsystemet er endnu ikke udført.** Softwaretestene
erstatter ikke kontrol af Debian 13/ARM64, rettigheder og de faktiske OpenSSH-logs.
Notér dato, Git-commit, Python-version, handling, forventning og resultat for
hver kontrol. Gem oplysninger fra rigtig drift privat, uden for repositoryet.

## 1 Installation og adgang

Følg [installationsvejledningen](../deploy/INSTALL_PI.md), kontrollér `uname -m`,
Python-version og tjenesternes status:

```bash
systemctl status yggdrasil-collector.service yggdrasil-web.service --no-pager
sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/yggdrasil-ids doctor --config /etc/yggdrasil-ids/config.toml --role collector --journal
sudo -u yggdrasil-web /opt/yggdrasil-ids/venv/bin/yggdrasil-ids doctor --config /etc/yggdrasil-ids/config.toml --role web
sudo -u yggdrasil-worker journalctl --system -n 1 --no-pager -o json
```

Den sidste kommando kontrollerer workerens journaladgang. En kontrol udført som
root dokumenterer ikke workerens rettigheder. Kontrollér også, at webkontoen ikke
er medlem af `systemd-journal`. Afprøv dashboardlogin gennem SSH-tunnelen.

## 2 Rigtige SSH-hændelser

Foretag ét normalt login fra en autoriseret klient til egen testserver. Kontrollér `_UID`, `_COMM`,
`__CURSOR` og tidsstempel i journalens JSON. Et `Accepted publickey`-resultat og
den tilhørende PAM-session skal give én vellykket autentificering.

Afprøv få kontrollerede fejl med en egen testnøgle, der ikke er autoriseret, og
bevar en fungerende administratorsession. Kontrollér først, hvilke fejlposter
din OpenSSH-konfiguration faktisk skriver. Parseren tæller `Failed …`-resultater;
en afbrudt forbindelse er ikke automatisk et fejlet login. Dokumentér andre
formater, før parseren udvides. Forsøget kræver ikke offentlig SSH-adgang eller
aktivering af adgangskodelogin.

## 3 Genstart og fejltilstande

```bash
sudo systemctl restart yggdrasil-collector.service
```

Kontrollér, at tidligere hændelses-ID’er ikke kommer igen som nye events, og at et
nyt login stadig vises. Stop og start collectoren kontrolleret; dashboardet skal
vise stoppet eller manglende heartbeat. Test utilgængelige logkilder og ugyldig
model i en isoleret testopsætning. Fejl må ikke fremstå som normal aktivitet.

## 4 Backup og model

Brug CLI-kommandoen `backup` med en ny filsti. Gendan kopien til en separat
testmappe og kontrollér SQLite samt historikken; overskriv ikke driftsdatabasen
som første gendannelsesforsøg.

Indsaml varieret normalaktivitet før træning. Gennemgå data og brug andre,
tidsadskilte forløb til test. Kontrollér modelversion, provenance og vinduesstørrelse.
Status uden en færdig model er forventet under indkøring; reglerne kan fortsætte.
Kontrollér også de valgte `expected_users` og `expected_sources`: en tom liste
deaktiverer den tilsvarende kontrol, og er ikke en vurdering af normal adfærd.

## 5 Forsinkelse og drift

Mål fra den journalpost, der udløser en regel, til alarmen er gemt, og særskilt
til den vises i dashboardet. Foreslåede acceptmål ved normal testbelastning er
højst to sekunder til registrering og ti sekunder til visning. Dashboardet henter
nye tal hvert femte sekund; det er ikke en garanti for samlet svartid. De faktiske
resultater skal måles på Pi’en.
Registrér også ML-tid, CPU, hukommelse, databaseplads og fejl over mindst 24 timers
drift. Udfyld de faktiske målinger frem for at overføre labresultater til serveren.
