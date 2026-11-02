# Sprint 4 – Isolation Forest, reproducerbar evaluering og produktionens datagrundlag

**Formål:** Færdiggøre og dokumentere AI-delen i Yggdrasil IDS inden eksamensrapporten. Sprint 4 er bevidst prioriteret før de foreslåede sudo-/filintegritetssprints. Ingen ændring af det aktive produktions-IDS indgår i denne første leverance.

## Acceptance: Hvad der faktisk kan dokumenteres

1. **Trænet model i isoleret lab.** Projektets eksisterende syntetiske SSH-datasæt har 312 *normale træningshændelser*. En model trænes på netop træningssplit og evalueres på holdte validerings- og sluttestsplit. Ingen data fra de holdte splits tilføjes under træning.
2. **Uafhængig test af tal.** Verifikationsscriptet sammenligner rå hold-out-forudsigelser i laboratorierapporten med TP/FP/TN/FN og genberegner precision, recall og falsk-positiv-rate. Det kontrollerer SHA-256 på kildefiler og labels samt adskilte tidsvinduer og model-fingerprint.
3. **Normaldata på Pi undersøges – ikke opfundet.** En read-only audit tæller SSH-events, feature-vektorer, perioder og modelstatus uden at udskrive IP-adresser, brugernavne, rå journalposter eller secrets. Den skaber ingen model.
4. **Dokumenteret sammenligning.** Rapporten skal beskrive både fordelene ved ML og dets falske positiver, samt at en afvigelse ikke er et bevis for angreb.
5. **Driftsadskillelse:** Den syntetiske model ligger i en privat labmappe og kopieres aldrig til produktionsmodellen uden en særskilt faglig og sikkerhedsmæssig beslutning.

## Udgangspunkt og allerede dokumenterede tal

Pi, 2. november 2026: **12 SSH-hændelser og 12 observationer**, minimum 80, modelstatus untrained, ingen produktionsmodelfil. Det er ikke nok til at evaluere eller træne en pålidelig personlig normalprofil.

Den historiske, versionerede **syntetiske laboratorietest** i examples/lab/report.md har 312 træningshændelser, 44 valideringshændelser og 41 sluttesthændelser.

| Sluttest (syntetisk) | TP | FP | TN | FN | Precision | Recall | Falsk positiv-rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SSH-regler | 12 | 1 | 21 | 7 | 92,3 % | 63,2 % | 4,5 % |
| Isolation Forest | 18 | 3 | 19 | 1 | 85,7 % | 94,7 % | 13,6 % |

ML registrerede flere af forsøgets konstruerede mistænkelige hændelser, men klassificerede også flere konstruerede normale hændelser som mistænkelige. **Metrikkerne gælder kun dette syntetiske testdesign.** Ved en ny generering kan tidsfeatures og scoring variere; brug altid den faktisk genererede rapport til den endelige tabel.

## Hvad modellen lærer

Den nuværende Isolation Forest analyserer **SSH-autentificeringer**, ikke portscan-hændelser. Seks features pr. kilde og rullende 300-sekundersvindue: antal fejl, antal succeser, antal forskellige brugernavne, andel fejlede forsøg og sinus/cosinus af UTC-tidspunktet. Antal event-drevne rækker er ikke antal uafhængige brugere eller sessioner.

Det er usuperviseret afvigelsesdetektion. Contamination=0,03 konfigurerer modellens tærskel og er **ikke** en målt angrebsprocent. En afvigelsesscore er ikke en sandsynlighed for intrusion.

## Eksamensdiskussion – et homelab med én bruger

12 SSH-observationer på en privat server med én primær administrator giver et sparsomt og typisk ensartet datagrundlag. Flere brugere i en virksomhed kan øge volumen, men samtidig gøre normalprofilen mere kompleks og øge risikoen for fejlklassifikation af legitime sjældne hændelser. 80 næsten ens logins kan ikke erstatte varierede, gennemgåede normalperioder.

Træningskvalitet skal derfor diskuteres via repræsentativitet, feature-variation, samplenes afhængighed, adskillelse mellem træning og test, dataforurening, falske positiver samt generaliserbarhed. Den nuværende labmodel må ikke beskrives som en model af virksomhedstrafik eller Yggdrasils private live-brug.

## Leverede filer

- deploy/sprint4_ml_readiness.py – aggregeret read-only audit af produktions-SSH, uden secrets.
- deploy/sprint4_verify_lab.py – verificerer datasplits, filhashes og forudsigelser mod confusion-matricer.
- deploy/sprint4_run_synthetic_lab.sh – opretter privat nyt lab med installeret CLI, træner og validerer syntetisk model uden at stoppe services.
- tests/test_sprint4_ml_evaluation.py – regressionstest for metrics, datalækage mellem splits, hash-tampering, autorisation og ingen databasewrites.
- docs/SPRINT_4_PI_RUNBOOK.md – præcise kommandoer til Pi, når ejeren er klar.

## Sprint 4 – acceptstatus

**GitHub-kode og tests:** Implementeret og verificeret via CI på Python 3.11 og 3.13 (Ruff, pytest og wheel-build). **På Pi:** laboratoriereproduktion og live SSH-readiness-rapport skal stadig køres af ejeren. **Live model:** untrained, indtil tilstrækkeligt gennemgået normaldata findes og modellen er særskilt accepteret. Dette er to forskellige former for accept.

Der indgår ingen upload af private screenshots, kilde-IP-adresser, passwords, token eller autentiske logs til GitHub.
