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

**Demostart bekræftet på Pi:** Det isolerede script fra commit `470052c465b65ace1188d78f64b0b474438c104d` gennemførte syntetisk model-/databaseoprettelse med `model.state=ready` og **41 scorede SSH-hændelser**. Gunicorn startede og loggede **`Listening at: http://127.0.0.1:8766`**. Pi's live-IDS på port 8765 var ikke ændret. **Visuel browseraccept af demoen på port 8766 er nu bestået** (screenshot af ML-status modtaget i samtalen). Brugeren sendte to screenshots fra produktionsdashboardet, der korrekt fortsat viste `Model ikke trænet`; de må ikke beskrives som screenshots af den trænede labmodel. Billederne er ikke uploadet til GitHub.

## Syntetisk ML-demo – browseraccept med screenshot

Brugeren loggede ind på den separate syntetiske demo på `127.0.0.1:8766/model` og sendte screenshot, der viser **`Model indlæst`** i grønt, 312 træningsobservationer, alarmgrænse **0,615**, scikit-learn **1.8.0**, træningstidspunkt **02.11.2026 kl. 03:44:45** og en tydelig provenance: *syntetiske normale SSH-labforløb fra train.jsonl; ingen validerings- eller testobservationer i træningen*.

**Demo-modelversion:** `ssh-if-bc574f0291c96358`. Det er en **ny og særskilt syntetisk demo-træning** og skal ikke forveksles med den verificerede, isolerede evalueringsmodels version `ssh-if-16ae0fc3a05948df` fra Pi's hold-out-forsøg. Der er derfor **to forskellige syntetiske modelartefakter**, hvilket er forventet.

**Bilag ML-C1:** screenshot af modelgrundlaget er modtaget i samtalen, **ikke uploadet til GitHub** og ikke automatisk indsat i eksamensrapporten. Ejer gemmer eventuelt originalen lokalt. **Bilag ML-C2:** screenshot af scorede modelvurderinger (41 testhændelser i demo) afventer stadig, helst med score og udfald. Slør private detaljer før offentlig rapportdeling. Produktionsmodellen på port 8765 er fortsat `untrained`.

## 7. Faktisk historisk SSH-journal på Pi – 2. november 2026

Ejeren kørte en **read-only** journal-audit via commit
`a3b80aed041bed54228e010a2a0cc919eea12f53`.
Den læser kun journalposter fra den allerede autoriserede OpenSSH-kilde,
bygger features midlertidigt i hukommelsen og viser kun aggregeret statistik.
**Ingen SSH-log, private IP-adresser eller personoplysninger er uploadet.**

| Opgørelse | Observation |
| --- | ---: |
| Journalposter undersøgt | 89 |
| Godkendte SSH-autentificeringer | **19** |
| Vellykkede / fejlede | **19 / 0** |
| Kilder (kun antal) | 1 |
| Dage med aktivitet | 5 |
| Unikke fulde feature-vektorer | 19 |
| Poster uden autentificeringsfund | 70 |

Journalhistorikken dækkede faktiske SSH-autentificeringer i perioden
24. oktober til 2. november. De **70 øvrige journalposter** er
ignorerede *eller* fejlfortolkede poster (den oprindelige audit
skelnede ikke); de er ikke 70 dokumenterede fejl eller angreb.

Den tidligere produktions-SQLite-kontrol viste **15 hændelser**.
Disse 15 og journalds 19 stammer fra overlappende SSH-kilder og
må **ikke** lægges sammen til 34 uafhængige observationer.
Journalens event-historik antyder lidt ekstra data, men der er
stadig lang vej til mindst 80 gennemgåede normale SSH-rækker
(mindst 61, selv hvis samtlige 19 kan bruges).

**Metodisk begrænsning:** `hour_sin` og `hour_cos` ændres med
klokkeslættet; derfor kan 19 forskellige fulde featurevektorer
eksistere uden tilsvarende 19 forskellige *adfærdsmønstre*.
Den opdaterede audit blev nu også kørt på Pi og fandt **præcis 2 forskellige adfærdsmæssige featurekombinationer uden tidskomponenterne**, mod 19 forskellige fulde vektorer. Dette er konkret evidens for lav adfærdsvariation, ikke blot lav datamængde.

**Faglig konklusion:** Der er ikke tilstrækkeligt verificeret
normalmateriale til at træne og aktivere en pålidelig
produktionsmodel inden den aktuelle projektfrist.
Det eksisterende syntetiske hold-out-forsøg er stadig en
fuldt gennemført software- og ML-evaluering, men er ikke
et estimat af produktionsmodellens detektionskvalitet.

## 8. Endelig ML-readiness-audit: 19 SSH-hændelser, men kun 2 adfærdsmønstre

**Kørsel på Pi:** `deploy/sprint4_ssh_journal_history.py` fra kildecommit `371cc355a1c395b1f2a8ffa85fede3fb50c262f4`. Scriptet læste kun OpenSSH-journalen, skrev intet til SQLite, udskrev ingen IP-adresser og ændrede ingen services.

| Måling | Verificeret på Pi |
| --- | ---: |
| Journalposter læst | 89 |
| SSH-autentificeringer | 19 |
| SSH-success / failure | 19 / 0 |
| Kilder (kun antal) | 1 |
| Dage med autentificeringer | 5 |
| Fuld-feature-vektorer, inklusive klokkeslæt | 19 |
| **Adfærdskombinationer uden tidsfeatures** | **2** |
| Ignorerede journalposter | 70 |
| Malformed journalposter | 0 |
| Krævede træningsobservationer (`min_samples`) | 80 |

**Faglig vurdering:** `hour_sin` og `hour_cos` skaber forskel mellem observationer på forskellige tidspunkter. Når disse to features fjernes fra variationsmålingen, er der kun to forskellige kombinationer af fejl/succes, antal brugernavne og fejlandel. Det er **ikke** to uafhængige brugere eller fuldstændigt identificerede brugsmønstre, men to distinkte fire-dimensionelle kombinationer. Denne meget begrænsede diversitet gør produktionstræning uegnet nu; vi vil ikke reducere teknisk minimum eller supplere med konstruerede loginforsøg alene for at få `ready`-status.

**Eksamensafgrænsning:** Den isolerede **syntetiske** Isolation Forest-træning og hold-out-evaluering er gennemført og verificeret; produktion forbliver bevidst `untrained` indtil et dokumenteret, varieret og manuelt gennemgået datasæt findes. Ny dokumentation om SSH-data må ikke forveksles med ændringer af det aktive produktions-IDS.
