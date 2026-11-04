# Produktionsaccept og eksamensbeviser

Den samlede release skal levere SSH-autentificering med regler og ML-alarmer,
SSH-preauth med regler, portscanning med regler og sudo med regler. Den skal
også bevare det loginbeskyttede dashboard og den eksisterende Discord-kæde.

## Status for den samlede release

Den 4. november 2026 blev release
`3ca24a114c52d2ac0ea24fe013d7c469db5b83e4` installeret på Yggdrasil.
Den indsendte opgraderingsrapport viste `status=ready`, SSH-model
`ssh-if-7cc1f15288d0c73b` med ML-alarmer aktiveret, aktive portscan- og
sudo-regler og bevaret notifier-identitet. Modellen blev ikke genoplært.

Efterfølgende indsendte skærmbilleder viste alle de valgte detektionsområder
i det fælles dashboard. Tabellen nedenfor skelner mellem disse observationer
og kontroller, der endnu ikke er dokumenteret med konkret evidens.
Der oplyses ingen gættet generel recall eller falsk-positiv-rate.

De tidligere forsøg og Pi-målinger er bevaret på den
[fastlåste udviklingsreference](https://github.com/Nox699/AI-Intrusion-Detection-System/tree/6abbc5d849973a9b15b2565ec7d25d66cc4effd8).
De dokumenterer tidligere versioner og kan ikke alene godkende den samlede
produktionsrelease.

## Observerede liveforløb den 4. november 2026

Alle klokkeslæt er Europe/Copenhagen (CET). Grundlaget er brugerens indsendte
terminalresultater og skærmbilleder; private journalposter og databaser er
ikke uploadet til GitHub.

| Tidspunkt | Forløb | Observeret resultat |
| --- | --- | --- |
| 02:22:37 | Almindeligt SSH-nøglelogin | Dashboardets modelobservation viste score 0,444 mod grænse 0,616: inden for grænsen. |
| 03:04:58 | Én forbindelse med en midlertidig, ikke-autoriseret testnøgle til den eksisterende konto | Modelobservationen viste score 0,647 mod grænse 0,616 og afvigelse. Dashboardet viste alarmen “Usædvanligt SSH-mønster”. Brugeren bekræftede modtagelse i Discord. |
| 03:10:48 | Forløb med fem nye afviste nøgleforbindelser | Dashboardet viste “Mange fejlede SSH-loginforsøg”, “Gentagne SSH-afbrud før login” og “Usædvanligt SSH-mønster”. Det er flere detektorfund under samme testforløb. |
| 03:16:02, teststart | TCP-connect-scanning af ti høje porte med 2 sekunders afstand | Nmap rapporterede ti filtrerede porte. Der blev ikke observeret en portscanalarm. Det efterfølgende diagram viste tre forskellige porte i det valgte udsnit; det er ikke en fuld audit af testens pakker. |
| 03:19:49, alarmtid | Ny scanning af 40 andre høje TCP-porte med 1 sekunds afstand | Dashboardet viste “Mulig TCP-portscanning”, med to fund samlet i ét alarmforløb. Antallet af fund er ikke antallet af forskellige porte. |
| 03:24:32, alarmtid | Sudo-test med tre afviste servicekontoprocesser | Dashboardet viste “Gentagne sudo-autentificeringsfejl”. |

Netværkskonfigurationen var fem forskellige destinationsporte inden for
60 sekunder. UFW var aktiv med logniveau `low`. Logbegrænsning er en mulig
forklaring på manglende synlighed i den mindre scanning; en sammenligning af
pakker på interfacet, kerneljournal og database er endnu ikke udført.

Før SSH-fejltestene blev laptopens enkelte Tailscale-adresse undtaget fra
Fail2bans `sshd`-jail. IDS-overvågningen fortsatte. OpenSSH-logning blev
eksplicit ændret fra INFO til VERBOSE med det særskilte
[vedligeholdelsesværktøj](https://github.com/Nox699/AI-Intrusion-Detection-System/tree/cb5e3a7f81e65be006552a98d500f6417aea5167).
Værktøjets rapport viste bevarede nøgleloginindstillinger og en gennemført
genindlæsning. Ingen adgangskodelogin blev aktiveret.

Brugeren bekræftede efterfølgende særskilt, at både portscan- og sudo-alarmen
også blev modtaget i Discord. Dermed er modtagelse brugerbekræftet for SSH-ML,
portscan og sudo. Der er endnu ikke indsendt et referencebaseret match mellem
de nye alarmers outbox-rækker og notifierkvitteringer. Alarmdetaljer med den
konkrete modelversion, evidens og leveringsreference bør gemmes privat.
Der er ikke dokumenteret en ny genstart af selve Pi'en efter disse tests.

## Målt lagerforbrug efter liveforløbene

Brugerens efterfølgende måling med `du`, `journalctl --disk-usage` og `df`
viste nedenstående afrundede værdier. Det er det samlede forbrug ved én
måling, ikke en måling af vækst pr. døgn.

| Placering | Rapporteret forbrug |
| --- | --- |
| Produktionsdata og model | 2,7 MiB |
| Privat sudo-historik | 236 KiB |
| Notifierens leveringshistorik | 20 KiB |
| IDS-backups | 278 MiB |
| Arkiveret og aktiv systemjournal | 49,5 MiB |
| Rodfilsystem | 1,8 TiB i alt; 22 GiB brugt; 1,7 TiB ledigt; 2 % anvendt |

Målingen gav ikke anledning til yderligere sletning. Anbefalingen var at
beholde 30 dages retention og produktionsdatabasebudgettet på 512 MiB
foreløbig. Den viste mængde dashboardposter og én lagermåling fastslår ikke
væksten ved senere større trafikmængder.

## Accept på målsystemet

| Kontrol | Det der skal dokumenteres |
| --- | --- |
| Release | Installeret commit og fælles kildeversion for alle driftsroller |
| Servicekonti | Worker, web og notifier starter med de tilsigtede rettigheder |
| SSH-model | Modellen er trænet, kan indlæses, matcher vinduet og er aktiveret til ML-alarmer |
| Indsamling | Frisk collector-heartbeat, journalposition og sudo-checkpoint; ingen skjult fejlkategori |
| Dashboard | Login virker på port 8765; relevante sider og readonly-adgang virker |
| Privatliv | Web kan ikke læse privat sudo-tilstand; eksporter indeholder kun de aftalte felter |
| Historik | Tidligere hændelser, alarmer, outbox-identitet og leveringsstatus er bevaret |
| Opstart | Tjenester og sudo-timer er enabled, og de genoptager efter et kontrolleret genstartforløb |
| Alarmkæder | Et særskilt kendt forløb for hver valgt detektor kan følges fra evidens til registreret alarm |
| Discord | Den konkrete alarms reference matcher en kvittering og den modtagne besked |

Opgraderingsværktøjets sundhedskontrol fremkalder ikke angreb eller nye
Discord-beskeder. Kontrollerede alarmforsøg er separate, bevidste handlinger i
det autoriserede lab. En sundhedskontrol kan bekræfte modelstatus og tilgængelig
kodevej; den beviser ikke i sig selv ny ML-detektion eller ny Discord-levering.

For SSH skal preauth og autentificering holdes adskilt. Et legitimt login
viser indsamling og scoring, men er ikke en positiv test af en ML-alarm.
Et regeludløst brute-force-fund beviser heller ikke, at ML fandt samme forløb;
ML-fundet skal have egen modelversion, score, tærskel og evidens.

## Allerede observeret før samlingen

Den tidligere sudo-integration blev kontrolleret på Yggdrasil med tre
afviste sudo-processer, ét regelfund, registreret alarm **4** og en matchet
Discord-kvittering. Referencen var `7ed92c291071761580e50cbbebbcfb39`.
Det viser én kontrolleret regel-til-Discord-kæde i den tidligere installation,
ikke alle sudo-reglers eller den nye releases generelle kvalitet.

Den 4. november 2026 kl. 01:11:04 Europe/Copenhagen bestod den tidligere
installations afsluttende sudo-driftskontrol fra
`e12d3f874e23382e8bcc3d7661b178fafda46903`. Den havde aktive regler, matchende
notifier-identitet og to samlede sudo-evidensrækker. Genkørslen ændrede ikke
unitfilen, genstartede ingen tjenester, migrerede ingen database og fremkaldte
intet nyt testforsøg. Den tidligere sudo-model var kun en sideløbende
forsøgsvurdering og indgår ikke i dette produkt.

Før samlingen var den dokumenterede SSH-model `ssh-if-7cc1f15288d0c73b`, baseret på
312 syntetiske normale og 12 gennemgåede virkelige observationer. Den havde
scoret et legitimt live-login, men sendte endnu ikke ML-alarmer. Den samlede
releases efterfølgende aktivering og observerede ML-alarm er beskrevet ovenfor.

## Prioriterede skærmbilleder til eksamen

1. Den samlede releases beståede driftskontrol med commit og SSH-modelversion.
2. Dashboardets oversigt og systemstatus efter opgraderingen.
3. En SSH-ML-alarm med score, tærskel, modelversion og det tilhørende forløb.
4. Et netværks- og et sudo-regelfund med konkret evidens og tidspunkt.
5. Den tilsvarende Discord-besked med en reference, der matcher alarmen.
6. Den grønne CI-kørsel eller pytest-rapport for den frigivne commit.

Gem originalerne privat. Slør credentials og private driftsoplysninger før en
offentlig deling. Et screenshot af en alarmtæller er svagere dokumentation end
en alarmdetalje med matchende evidens og leveringsreference. Én vellykket test
må ikke omregnes til en generel detektionsrate.
