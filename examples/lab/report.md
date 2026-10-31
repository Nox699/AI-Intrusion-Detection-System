# Laboratorietest af SSH detektion

**Syntetisk softwaretest. Resultaterne dokumenterer disse konstruerede forløb og er ikke en sikkerhedsbenchmark for Raspberry Pi’en.**

Model: `ssh-if-5dc2863023cdd10b`. Træningsobservationer: 312. Vindue: 300 sekunder.

Træning, validering og sluttest består af adskilte tidsperioder. Modellen trænes kun på normaldelen. Validering og test ændrer ikke indstillingerne.

| Datasæt | Metode | TP | FP | TN | FN | Precision | Recall | Falsk positiv-rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Validering | Regler | 13 | 1 | 23 | 7 | 92.9 % | 65.0 % | 4.2 % |
| Validering | Isolation Forest | 19 | 3 | 21 | 1 | 86.4 % | 95.0 % | 12.5 % |
| Sluttest | Regler | 12 | 1 | 21 | 7 | 92.3 % | 63.2 % | 4.5 % |
| Sluttest | Isolation Forest | 18 | 3 | 19 | 1 | 85.7 % | 94.7 % | 13.6 % |

TP = opdaget simuleret mistænkelig hændelse; FP = alarm ved legitim aktivitet; TN = legitim aktivitet uden alarm; FN = overset simuleret mistænkelig hændelse.

Precision = TP/(TP+FP). Recall = TP/(TP+FN). Falsk positiv-rate = FP/(FP+TN). Nævnerne og resultater pr. scenarie findes i report.json. Hændelser tælles før gruppering til alarmforløb.

## Begrænsninger

- Syntetiske software- og demonstrationsdata; resultaterne er ikke en sikkerhedsbenchmark for Pi’en.
- En observation er ét autentificeringsresultat. Overlappende vinduer gør observationerne afhængige.
- Scenariernes hensigt er kendt fra forsøget. Logs alene beviser ikke ondsindet hensigt.
- Træningen bruger kun den separate normaldel. Validering og sluttest ændrer ikke modellen eller alarmgrænserne.
- Første forsøg i et simuleret angrebsforløb kan ligge under reglernes tærskel og tæller derfor som oversete hændelser.
- Precision, recall og falsk positiv-rate beskriver kun disse konstruerede forløb og deres valgte fordeling.

Det legitime login fra en ny kilde er bevidst medtaget for at vise, at en afvigelse fra normalprofilen også kan have en legitim forklaring.
