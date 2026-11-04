# Produktionsaccept og eksamensbeviser

Den samlede release skal levere SSH-autentificering med regler og ML-alarmer,
SSH-preauth med regler, portscanning med regler og sudo med regler. Den skal
også bevare det loginbeskyttede dashboard og den eksisterende Discord-kæde.

## Status for den samlede release

Softwaretests og validering af opgraderingsforløbet udføres på den nye gren.
**Den samlede release er ikke dokumenteret som installeret og accepteret på
Pi'en endnu.** Installeret commit, ny SSH-modelstatus og kontrollerede
alarm-/leveringsresultater skal registreres efter den konkrete opgradering.
Der oplyses ingen gættet generel recall eller falsk-positiv-rate.

De tidligere forsøg og Pi-målinger er bevaret på den
[fastlåste udviklingsreference](https://github.com/Nox699/AI-Intrusion-Detection-System/tree/6abbc5d849973a9b15b2565ec7d25d66cc4effd8).
De dokumenterer tidligere versioner og kan ikke alene godkende den samlede
produktionsrelease.

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

Den sidst dokumenterede SSH-model var `ssh-if-7cc1f15288d0c73b`, baseret på
312 syntetiske normale og 12 gennemgåede virkelige observationer. Den havde
scoret et legitimt live-login, men sendte endnu ikke ML-alarmer. Den nye
installation skal derfor dokumentere bevidst aktivering og en efterfølgende
ML-alarm, før denne del beskrives som live-accepteret.

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
