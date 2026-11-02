# Sprint 4 – verificeret AI/Isolation Forest-forsøg på Raspberry Pi

**Dato:** 2. november 2026 (Europe/Copenhagen).
**Kode:** `c3c9def02eba51e05c8ecd9902462c1a9a22d887` på `sprint-4/ml-evaluation`.
**Dataklassifikation:** Laboratoriet anvender syntetisk genererede SSH-journalhændelser. Her publiceres **kun aggregerede forskningsresultater og syntetiske filhashes**. Ingen produktions-SQLite, autentiske journalposter, IP-adresser, screenshots eller credentials er uploadet.

## 1. Produktionsdata – kontrol uden ændringer

Brugeren gennemførte `deploy/sprint4_ml_readiness.py` via `git show` med den **installerede** Python som `yggdrasil-worker`. Den læste SQLite i `mode=ro` og gav følgende verificerede målinger:

| Mål | Resultat |
| --- | ---: |
| SSH-events / observationsrækker | 15 / 15 |
| Succesfulde / fejlede autentificeringer | 15 / 0 |
| Aktive dage | 3 |
| Distinkte kildeadresser (antal, ikke adresser) | 1 |
| Unikke feature-vektorer | 15 |
| Minimum for modeltræning | 80 |
| Mangler til teknisk minimum | 65 |
| Modelstatus / modelfil | `untrained` / nej |
| Produktions-træningsgodkendelse | `false` |

**Fortolkning:** De 15 forskellige feature-vektorer dokumenterer ikke 15 uafhængige normale adfærdsmønstre. Alle observerede SSH-autentificeringer var succeser fra én kilde. Tidsfeatures ændres også mellem ellers ens logins. Datagrundlaget er hverken tilstrækkeligt eller manuelt gennemgået til en dokumenteret produktionsmodel.

## 2. Trænet syntetisk Isolation Forest – gennemført

Brugeren gennemførte `deploy/sprint4_run_synthetic_lab.sh` som den almindelige Pi-bruger. En privat ny labmappe blev oprettet, og den installerede CLI trænede en **ny model** udelukkende med syntetisk normaltræning. Ingen produktionsfiler, systemd-services eller produktionsmodel blev ændret.

| Datasplit | Hændelser | Formål |
| --- | ---: | --- |
| Træning | **312** | Kun syntetiske normaldata, tilpasning af Isolation Forest |
| Validering | **44** | Adskilt evaluering |
| Sluttest | **41** | Uafhængigt hold-out-forsøg |

**Modelversion:** `ssh-if-16ae0fc3a05948df`.
**Featurevindue:** 300 sekunder.
**Rapport (syntetisk) SHA-256:** `51fefd76bef6b661c9537b08f5ed97fd46c697cc3eacef576b8a7bde2b4f59d4`.
**Modelartefakt (syntetisk) SHA-256:** `bfa01ffc4c46f927c76e769c91e112a65467d74feae79233fbf81d9408bfc6d3`.

Laboratorie-verifikatoren kontrollerede separate splits, SHA-256 på datasæt og labels, modelversion og træningsminimum samt TP/FP/TN/FN/precision/recall/false-positive-rate på *alle* validerings- og testhændelser. Den kontrollerer facitliste mod rapportens hændelser, regelsignaler og modelscore mod grænse.

## 3. Resultater

| Datasæt | Metode | TP | FP | TN | FN | Precision | Recall | Falsk positiv-rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validering | Regler | 13 | 1 | 23 | 7 | 92,9 % | 65,0 % | 4,2 % |
| Validering | Isolation Forest | 19 | 4 | 20 | 1 | 82,6 % | 95,0 % | 16,7 % |
| Sluttest | Regler | 12 | 1 | 21 | 7 | 92,3 % | 63,2 % | 4,5 % |
| Sluttest | Isolation Forest | 18 | 3 | 19 | 1 | 85,7 % | 94,7 % | 13,6 % |

**På sluttesten:** 19 syntetisk mistænkelige og 22 normale hændelser. Isolation Forest fandt 18/19 frem for reglernes 12/19, men havde 3/22 falske positive frem for reglernes 1/22. Tallene angiver hændelser **før** gruppering til alarmforløb. Forskellen i valideringens FP fra den tidligere versionerede eksempelrapport (3→4) er forenelig med, at nye syntetiske tidsstempler ændrer tidsfeatures; forskellen er ikke i sig selv dokumentation for en kodeændring.

## 4. Driftskontrol og integritet

**Før og efter lab-forsøget:** `yggdrasil-collector.service`, `yggdrasil-web.service`, `yggdrasil-notifier.service` rapporterede alle `active`. Scriptet afsluttede med `PASS: Kun isoleret labmodel og evalueringsrapport er genereret.`

**Hovedkonklusion:** En Isolation Forest-model er faktisk trænet og evalueret på Raspberry Pi, men **produktionsmodellen er stadig ikke trænet**. Vi demonstrerer ML-teknikken reproducerbart uden at påstå uafhængig reel driftsaccuracy.

## 5. Begrænsninger og diskussionspunkter til eksamensopgaven

- Testscenarierne er konstruerede; labels er kendt fra forsøgsdesignet. De giver **ikke** estimater for ukendte angreb eller virksomheds-/homelabtrafik.
- Event-drevne observationer inden for 300 sekunder kan overlappe og dermed være statistisk afhængige.
- Variation i syntetiske tider giver variation i features og modelscore. Den nye validering havde 4 frem for 3 falske positiver for ML; korrekt rapport skal anvende **den nye kørsel**.
- En privat Pi med én primær SSH-bruger producerer få og relativt ensartede observationer; virksomheder kan give flere hændelser, men også mere heterogen normaladfærd.
- En afvigelsesscore er **ikke** sandsynligheden for angreb; miljøafhængige tærskler og falske positiver skal diskuteres.
- Isolation Forest implementeres aktuelt kun på SSH-features. Sprint 3's TCP-portscanningsdetektion er **regelbaseret**, ikke en separat trænet netværksmodel.

## 6. Resterende demonstration og bilag

**ML-A:** Produktionsaudit 15/80 og `untrained` (kun aggregerede tal).
**ML-B:** Ny labrapport og verifikatorens sammenligningstabel, tydeligt mærket *syntetisk laboratorietest*.
**ML-C:** Valgfri ML-demo på 127.0.0.1:8766 gennem SSH-tunnel, med *trained/ready* i et særskilt LAB-dashboard og screenshot privat.
**ML-D:** CI/pytest/ruff-dokumentation samt Git-commit for koden.

**Næste handling:** Ejer kan køre `deploy/sprint4_ml_demo_dashboard.sh` efter grøn CI. Der er ingen behov for at installere Sprint 4-koden i produktions-venv; scriptet anvender eksisterende CLI. Demoen skal stå på **en anden loopback-port** end produktionsdashboardet.
