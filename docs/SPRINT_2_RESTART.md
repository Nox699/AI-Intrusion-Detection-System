# Sprint 2 — Discord-notifikationer, ny start

**Status: design og acceptkriterier. Ikke en færdig implementering eller installationsvejledning.**

Denne branch starter fra Sprint 1-commit `14b66943cf49b9915c5832f957903b2aa9c79789`.
Den tidligere branch `feature/discord-notifier` bevares som uafsluttet udkast,
men indgår ikke i denne branch. `main` og den installerede Pi-version ændres ikke
ved oprettelsen af dette dokument. Der må ikke installeres fra det tidligere
udkast alene på grundlag af denne plan.

## Mål og afgrænsning

En ny relevant IDS-alarm skal kunne give en kort, forståelig besked i en privat
Discord-kanal. Leveringsfejl må ikke stoppe SSH-indsamlingen. Ejeren skal kunne
se forskel på en gemt alarm, en afventende notifikation og en besked kvitteret
modtaget af Discord. En kvittering er ikke bevis for, at telefonen viste en
pushnotifikation, eller at et menneske læste beskeden.

Sprintet omfatter webhook, privat hemmelighedshåndtering, vedvarende kø,
kontrollerede genforsøg, begrænsning af gentagne beskeder, driftsstatus,
installation og accepttest. Det omfatter ikke en Discord-chatbot, offentlig
webadgang, automatisk blokering, nye SSH-rettigheder eller nye ML-features.
Daglige/ugentlige rapporter forbliver en senere udvidelse.

Der oprettes ikke en særskilt Discord-brugerkonto til programmet. En incoming
webhook til en udtrykkeligt valgt privat tekstkanal er tilstrækkelig.

## Gennemgang af det tidligere udkast

Udkast gennemgået: `0a485ff2296725a705617d3314d7f760c04d9458`.
Dets CI-kørsel `41261133467` er afsluttet med fejl; den må ikke beskrives som
softwaregodkendt. Fundene nedenfor er adskilt fra CI-resultatet.

| Fund | Risiko | Krav til den nye løsning |
| --- | --- | --- |
| HTTP-koden læser kun 1.024 bytes og forsøger derefter at JSON-afkode svaret. | Et længere, gyldigt svar kan blive afkortet. En faktisk leveret besked kan derfor blive behandlet som en fejl og forsøgt sendt igen. | Afgrænset, men tilstrækkelig svarlæsning; tydelig håndtering af for store/ugyldige kvitteringer; test med svar over 1 KB. |
| Udvælgelsen bruger kun `id > last_id`, mens `alerts.id` er en almindelig SQLite `INTEGER PRIMARY KEY`. | Efter sletning/retention kan et ID genbruges, så nye alarmer overses. | Stabil notifikationsidentitet og holdbar kø. Test retention, genbrugte ID'er og databasegendannelse. |
| `Retry-After` forkortes til højst 300 sekunder, og JSON-feltet `retry_after` bruges ikke. | Genforsøg kan ske tidligere, end Discord tillader. | Serverens ventetid må ikke forkortes. HTTP-header, JSON-felt og global ratebegrænsning indgår i tests. |
| Leveringen afhænger af, at alarmen stadig findes i kildedatabasen ved næste læsning. | Et leveringsproblem kombineret med retention kan medføre tab af endnu ikke leverede notifikationer. | Materialisér et minimalt beskedgrundlag i en vedvarende kø før netværksafsendelse; definer kapacitet, retention og synlige fejl. |
| En permanent webhookfejl afslutter løkken uden fejlstatus til processen. | Tjenesten kan se ud til at være afsluttet normalt, selvom notifikationer er stoppet. | Synlig fejltilstand og kontrolleret stop/genoptagelse uden en genstartsløkke. |

To mekanismer er reproduceret i små, isolerede Python/SQLite-forsøg: et ID blev
genbrugt efter sletning og overset af `id > last_id`, og et gyldigt JSON-svar
blev uafkodeligt efter afkortning til 1.024 bytes. Det er ikke en gennemført
end-to-end-test af det tidligere modul eller en Discord-leveringstest.

## Designkrav

### 1. Holdbar levering uden at koble netværk til collectoren

Den ønskede kæde er:

```text
SSH-journal -> collector og detektorer -> lokal alarm + notifikationsgrundlag
                                                  |
                                                  v
                            separat notifier -> vedvarende leveringskø
                                                  |
                                                  v
                                           Discord via HTTPS
```

En lokal, transaktionel outbox er det foretrukne udgangspunkt: oprettelsen af en
ny alarm og dens notifikationsgrundlag skal høre sammen. Collectoren må ikke
foretage Discord-netværkskald. Notifieren har læseadgang til den relevante
kildedata og skriver kun til sin egen leveringsstatus/kø. Detaljer om skema og
identiteter fastlægges og testes før en migration anbefales på Pi'en.

Netværkskald må aldrig holde en skrivetransaktion i driftsdatabasen åben.
En manglende/defekt kø må ikke nulstilles lydløst. Køkapacitet og fuld disk skal
være observerbare fejl, ikke et skjult tab af beskeder.

### 2. Beskedpolitik

- Standard: send nye alarmforløb med niveau `medium`, `high` eller `critical`.
- Ét alarmforløb udløser som udgangspunkt én notifikation; nye fund i samme
  forløb skal ikke automatisk sende en besked for hvert SSH-forsøg.
- `ssh.preauth_burst` skal medtages. Beskeden må ikke omdøbe et observeret
  preauth-mønster til et bekræftet nøgleangreb.
- Første aktivering skal have en eksplicit startgrænse. Eksisterende historik
  sendes ikke som nye alarmer. Senere genstarter må ikke flytte denne grænse og
  kassere afventende beskeder.
- Valg af alarmniveau og lokale afsendelsesgrænser dokumenteres i konfigurationen.
  Ændring af niveau skal have en beskrevet virkning på allerede kølagte beskeder.
- Standardbeskeden indeholder serverlabel, stabil alarmreference, type,
  alvorlighed og tidsstempel. Brug kontrollerede detektortekster i stedet for
  vilkårlig tekst fra logs. Ingen IP-adresser, brugernavne, nøgler eller rå logs
  sendes som standard.
- Deaktivér mentions med `allowed_mentions`. Ingen masse-pings eller embeds
  baseret på ukontrolleret logindhold.
- Medtag ikke et localhost-link som om det kunne åbnes direkte på telefonen.

### 3. Discord-transport og fejl

Brug HTTPS med certifikatkontrol, en eksplicit godkendt Discord-webhookadresse
og `wait=true`. Følg ikke HTTP-redirects med den hemmelige webhookadresse.
Begræns request- og response-størrelse og alle netværksoperationer så vidt
biblioteket tillader; dokumentér eventuelle begrænsninger i DNS/timeouts.

| Situation | Ønsket adfærd |
| --- | --- |
| Gyldig beskedkvittering | Gem Discord-besked-ID og leveringstid atomisk lokalt. |
| Timeout, netværksfejl eller midlertidig serverfejl | Bevar beskeden og planlæg genforsøg med stigende ventetid. |
| HTTP 429 | Overhold serverens ventetid; gem pausen, så en procesgenstart ikke omgår den. |
| Ugyldig, slettet eller utilstrækkeligt autoriseret webhook | Stop/pausér levering tydeligt; ingen hurtig uendelig genforsøgsløkke. |
| Gentagne fejl | Synlig fejlstatus og eksplicit genforsøg/genoptagelse; ikke lydløst tab. |
| Crash efter Discord-modtagelse, før lokal kvittering er gemt | Mulig dublet dokumenteres. Lov ikke 'præcis én gang'. |

En leveret HTTP-kvittering og en mobilnotifikation er to forskellige
acceptkriterier. Afsendelse må ikke genforsøges blot fordi en telefon er lydløs.

### 4. Rettigheder og hemmeligheder

- Bevar collectorens eksisterende netværksisolering og separate webkonto.
- Notifieren får egen systemkonto uden interaktivt login og uden
  `systemd-journal`-medlemskab. Den må ikke skrive til IDS-databasen.
- Foretræk en root-ejet webhookfil med mode `0600`, indlæst via systemd
  `LoadCredential`. Notifieren læser credential-filen ved kørsel.
- Den rigtige webhook må aldrig stå i Git, kommandolinjeargumenter, chat,
  screenshots, exception-tekster eller webdashboardet. Eksempelfiler indeholder
  ingen fungerende URL eller token.
- Leveringskøen er privat. Webdelen får højst en separat, begrænset
  statusoversigt, ikke webhooken eller skriverettigheder til køen.
- Programmet skal ikke importere/træne ML-modeller blot for at sende en besked.
- Ingen nye indgående firewallporte, ingen ændring af SSH-nøgler,
  Fail2ban eller Tailscale. Notifieren åbner ikke en webserver.

## Implementeringsrækkefølge

1. Definér notifikationsidentitet, køtilstande, første start og retention.
   Skriv regressionstests for de identificerede fejl før integration.
2. Implementér kø og Discord-transport med simuleret HTTP-modtager og ur.
   Tests må ikke kontakte Discord eller kræve en rigtig webhook.
3. Tilkobl eksisterende alarmtyper uden at ændre deres detektionskriterier.
   Tilføj rolleopdelt driftsstatus, sikker credential-oprettelse og servicefil.
4. Kør hele eksisterende testsuite samt de nye tests, lint og formatering,
   byg pakken og kontrollér installeret pakke. CI skal være grøn på de
   understøttede Python-versioner før installationsinstruktioner gives.
5. Foretag en kontrolleret Pi-opdatering med frisk backup og dokumenteret
   rollback. Send først én tydeligt mærket testbesked og derefter én rigtig,
   kontrolleret IDS-alarm til den valgte kanal. Kontrollér telefonen særskilt.

## Acceptkriterier og testmatrix

| ID | Kontrol | Krævet resultat |
| --- | --- | --- |
| N01 | Ny `preauth_burst` over grænsen | Korrekt alarmreference og alvorlighed i én besked. |
| N02 | Normalt, godkendt SSH-login | Ingen ny alarm og ingen alarmnotifikation. |
| N03 | Flere fund i samme alarmforløb | Ingen besked pr. loglinje; den valgte grupperingspolitik overholdes. |
| N04 | Netværksfejl og procesgenstart | Køen består, og kun ikke-kvitterede beskeder forsøges igen. |
| N05 | Genbrugt/slettet alarm-ID, retention og restore | Ingen tavst oversete nye beskeder; inkonsistent historik vises som fejl. |
| N06 | Discord-svar over 1 KB | Gyldigt svar håndteres uden falsk leveringsfejl. |
| N07 | 429 med decimaler, header/JSON og lang ventetid | Ingen afsendelse før den krævede ventetid; også efter genstart. |
| N08 | 400/401/403/404, redirect og ugyldigt JSON | Klassificerede, synlige fejl uden tokenlæk eller afsendelsesstorm. |
| N09 | Afbrudt proces omkring transaktion/kvittering | Bevarede lokale data; den beskrevne dubletrisiko er testet. |
| N10 | To samtidige notifierprocesser | Én ejer af kø/afsendelse; den anden afvises sikkert. |
| N11 | Webhookfil, mentions og logindhold | Ingen hemmeligheder i output; mentions deaktiveret og datadeling begrænset. |
| N12 | Collector mens Discord fejler | SSH-indsamling og lokale alarmer fortsætter. |
| N13 | Første start og efterfølgende genstarter | Ingen historisk beskedflod; ingen implicit kassering af ventende beskeder. |
| N14 | Leveringsstatus | Kø, seneste kvittering, fejl og forældet heartbeat fremgår tydeligt. |
| N15 | Pi og telefon | Faktisk besked modtaget i valgt kanal; telefonindstillinger afprøvet særskilt. |

Ingen af N01–N15 er erklæret bestået af dette dokument. Testresultater skal
registreres med commit, miljø, handling, forventning og faktisk resultat.
Syntetiske testdata og rigtig drift holdes fortsat adskilt.

## Første forberedelse hos ejeren

Opret eller vælg en privat Discord-server og tekstkanal til projektet,
for eksempel `#ids-alarmer`. En webhook kan oprettes under serverens
integrationer og knyttes til denne kanal. Gem URL'en privat, eller vent med at
kopiere den til installationen. URL'en skal ikke sendes til udviklingschatten.
Der er endnu ingen Sprint 2-installationskommandoer at køre på Pi'en.

## Forhold fra Sprint 1, som stadig skal følges

De demonstrerede SSH-logins, preauth-visning og regelalarm er et verificeret
udgangspunkt fra brugerens accepttest. Det gør ikke hele systemet
produktionscertificeret. Live-Isolation-Forest mangler fortsat et gennemgået
normaldatagrundlag. Længere tids drift og de resterende acceptkontroller
skal dokumenteres særskilt. WSL's tidligere MTU-rettelse var midlertidig;
den er ikke gjort permanent som del af dette sprint.

## Kilder og gennemgået kode

- Tidligere notifier: `feature/discord-notifier`, commit
  `0a485ff2296725a705617d3314d7f760c04d9458`, `src/yggdrasil_ids/notify.py`.
- Sprint 1-skema: `14b66943cf49b9915c5832f957903b2aa9c79789`,
  `src/yggdrasil_ids/storage.py`.
- Discord webhook API: https://docs.discord.com/developers/resources/webhook
- Discord rate limits: https://docs.discord.com/developers/topics/rate-limits
- Discord webhook-oprettelse: https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks
- SQLite ROWID/genbrug: https://www.sqlite.org/autoinc.html
- systemd credentials: https://systemd.io/CREDENTIALS/

De eksterne kilder er gennemgået den 1. november 2026. Designkravene ovenfor er
projektets beslutninger og anbefalinger, ikke garantier fra leverandørerne.
