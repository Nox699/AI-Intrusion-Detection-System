# Sprint 5 – Isolation Forest til sudo (eksperiment, ikke produktionsalarm)

**Status (3. november 2026):** Særskilt modelkode og syntetisk
ML-versus-regler-laboratorium er tilføjet til udviklingsbranchen.
Det eksisterende aktive `yggdrasil-sudo-shadow.timer` forbliver
**regelbaseret og uændret**, indtil denne evaluering er
gennemført og de nødvendige sikkerhedsacceptkriterier er bestået.

## Hvorfor en særskilt sudo-model?

SSH-modellens seks features beskriver autentificering via kilder
og brugernavne. Sudo-modellen må ikke score disse felter, fordi
sudo er **lokale privilegiehandlinger**, ikke indgående SSH-sessioner.
Regelmotoren har allerede demonstreret tre distincte fejlede
sudo-processer og to separate VM-forløb.

Et almindeligt sudo-kald kan give tre eller flere journald-poster:
kommando, PAM-session åben og PAM-session lukket.
Ved fejlede forsøg kan PAM-auth-fejl og password-summary
være **samme sudo-proces**. Sudo-ML bygger derfor
én observation pr. `(boot_id, uid, pid)`-gruppe
og anvender **aldrig én observation pr. loglinje**.

## Fast featuredefinition (300-sekundersvindue)

| Feature | Beskrivelse |
| --- | --- |
| `processes_300s` | Antal forskellige sudo-processer pr. boot/UID |
| `failed_processes_300s` | Processer med PAM-/password-fejl |
| `denied_processes_300s` | Processer med eksplicit `not_in_sudoers` |
| `successful_processes_300s` | Succesindikerende kommando- eller sessionåbning |
| `failure_ratio_300s` | (Fejlede + afviste) / samlede processer |
| `hour_sin` | Døgnrytme som cirkulær UTC-tidsfeature |
| `hour_cos` | Døgnrytme som cirkulær UTC-tidsfeature |

**Privatliv:** Ingen `MESSAGE`, `COMMAND`, brugernavn,
IP-adresse, `uid`, `pid` eller journalcursor bliver en
model-feature. De tekniske UID/PID/boot-felter bruges
kun midlertidigt i hukommelsen til proceskorrelation.
Ved PID-genbrug, loginidentiteter og samtidige sudo-processer
er denne første korrelation en **approksimation**,
som kræver senere reel datavalidering.

## Forsøgsdesign

1. `SudoIsolationForest` er separat fra SSH- og
   preauth-modellerne: versioneret **JSON-artifact**,
   SHA-256-fingerprint, låst featurekontrakt,
   identisk scikit-learn-version ved indlæsning,
   `n_estimators=128`, `contamination=0.03`,
   `random_state=42`.
2. **Normaltræning:** 180 separate, deterministiske og
   **syntetiske** scenarier, herunder almindelig sudo,
   vedligeholdelsesbursts, enkeltstående fejl/typos,
   travl normalaktivitet og tidsmæssigt adskilte kald.
   Ingen rigtige Yggdrasil-logs blandes i træningen.
3. **Validering:** 32 nye normale og 32 mærkede
   simuleret mistænkelige scenarier.
   **Sluttest:** yderligere 32 normale og 32 mistænkelige
   scenarier, med egne seeds og ingen scenarier delt
   mellem træning, validering og test.
4. **Mærkede mistænkelige scenarier:**
   gentagne password-fejl, eksplicit sudoers-afvisning,
   kombinerede auth- og adgangsfejl og langsomme fejl.
   Labels repræsenterer *forsøgsdesign*, ikke
   bekræftede angreb. En enkelt forkert adgangskode
   er med vilje også repræsenteret som normal adfærd.
5. Både `SudoRuleDetector` og den trænede
   `SudoIsolationForest` vurderer **præcis de samme
   scenarier**. Et scenario er markeret af en metode,
   hvis mindst én proces gav en kandidat/anomalisk score.
   Rapporten viser **TP, FP, TN, FN, precision, recall
   og false-positive-rate pr. scenario**; den angiver
   eksplicit, at tallene ikke er produktionsmål.
6. Model og `report.json` gemmes i en
   **privat mappe under `~/yggdrasil-sudo-ml-private`**,
   ikke i repo, produktionens datastier eller
   `sudo-shadow`-databasen.
7. CI skal bestå med pytest, Ruff og wheel på
   Python 3.11 og 3.13, før vi kører på Pi.

## Fortolkning og stopkriterier

- ML er ikke automatisk bedre. Hvis den har flere
  falske positiver eller overser kendte sudo-fejl,
  skal reglerne fortsat være primær detektion.
- En Isolation Forest-score er **ikke** sandsynligheden
  for et angreb; den er et mål for afvigende observationsmønster.
- Selv en god syntetisk sluttest dokumenterer
  **ikke** virkelige angribere eller en produktions-FPR.
  De 75 tidligere observerede sudo-journalposter på Pi
  omfatter kun ca. 25 normale kommando/sessionforløb
  og er **ikke** 75 uafhængige normale ML-eksempler.
- Efter syntetisk evaluering kan vi foretage
  **separat, læsebaseret scoring** af tilgængelige
  rigtige sudo-data under worker-rettigheder for
  at vurdere støj og featurevariation – uden at
  kalde det en statistisk estimeret false-positive-rate.
- Kun hvis data og evaluering forsvarer det, kan
  en ny sudo-model senere optages i shadow-sensoren;
  Discord og produktions-alarm-outbox skal fortsat
  være adskilt, medmindre vi laver særskilt gated integration.

**Screenshot-forslag S5-14:** Syntetisk sudo-IF-versus-regler
på validation og låst test; tydelig markering af
`synthetic_only=true` og de faktiske TP/FP/TN/FN.
Dette er bedst som dokumentation for **kritisk modelvalg**,
ikke som bevis på beskyttelse mod ukendte angreb.

## Praktisk Pi-benchmark – 3. november 2026

**Kørt af ejer på Yggdrasil** som et isoleret syntetisk forsøg
fra kildecommit `0cd25bdc666a68625513e2f6b5bcc2d40e84ef5f`.
Træning: **180 separate normale syntetiske scenarier**,
**681 procesbaserede træningsobservationer**.
Model `sudo-if-4f95328112e7423b`,
tærskel `0.6480873096476828`.

**Validering: 64 scenarier (32 normale / 32 syntetisk mistænkelige)**

| Metode | TP | FP | TN | FN | Precision | Recall | FP-rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Regler | **24** | **0** | 32 | 8 | 100 % | **75 %** | **0 %** |
| Isolation Forest | 15 | 5 | 27 | 17 | 75 % | 46,88 % | 15,62 % |

**Låst sluttest: 64 helt nye scenarier (32 normale / 32 syntetisk mistænkelige)**

| Metode | TP | FP | TN | FN | Precision | Recall | FP-rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Regler | **24** | **0** | 32 | 8 | 100 % | **75 %** | **0 %** |
| Isolation Forest | 12 | 4 | 28 | 20 | 75 % | 37,5 % | 12,5 % |

**Teknisk accept:** De to metoder blev faktisk evalueret på
de samme **syntetiske** scenarier, men reglerne vandt i
begge split på recall og på falsk-positiv-rate.
En regelfri sudo-Isolation-Forest må derfor **ikke**
erstatte regeldetektionen eller udløse aktive
produktionsalarmer på baggrund af denne test.
`synthetic_only=true`,
`real_journald_records_read=0`,
`production_sudo_shadow_modified=false`,
`production_ml_model_modified=false`,
`production_database_modified=false` og
`discord_messages_sent=0`.

**Fagligt forbehold:** Tallet `FP-rate=0` for regler
betyder **0 ud af kun 32** mærkede normale,
kunstigt konstruerede scenarier; det er *ikke*
Yggdrasils faktiske false-positive-rate.
Nogle features er nært koblet til de allerede
kendte regelsignaler, og "mistænkelig" er et
scenarielabel – ikke dokumentation for kompromittering.
En mulig forbedring af modellen skal bestemmes
fra trænings- og valideringsdata og siden
efterprøves på **et nyt** sluttestsæt, ikke
optimeres mod denne allerede anvendte sluttest.

**Privat forsøgsmappe (kun ejeren):**
`~/yggdrasil-sudo-ml-private/sudo-if-20261103T101759-143223`.
Her ligger `sudo-model.json` og `report.json`.
Ingen model fra denne mappe er aktiveret i
produktions-sudo-shadow. Laboutput omfatter ingen
rå journalposter.

**Screenshot S5-14:** Fang begge metoder med TP/FP/TN/FN
for sluttesten, og at data er mærket `synthetic_only`.
Dette er egnet som evidens for **kritisk
modelvurdering**, ikke "AI er bedst".
