# Isolation Forest – Pi baseline og træningsplan

**Observation (2. november 2026):** Yggdrasil har 12 SSH-hændelser, 12 observationer med state untrained, minimum 80 observationer, ingen modelfil, og modelstatus untrained. Det er brugerens read-only SQL-måling på Pi, ikke en estimering.

**Fortolkning:** Mindst 68 ekstra rækker kræves numerisk for at nå minimum; 80 rækker er dog ikke i sig selv garanti for egnede normale træningsdata. De 12 registreringer er ikke blevet klassificeret som normale eller mistænkelige. UFW-portscanninger tæller ikke som SSH-features. Den regelbaserede overvågning og Discord fungerer fortsat, selvom ML ikke er trænet.

## Anbefalet fremgangsmåde

1. Lad realtids-SSH/portscanning køre, og indsamle almindelig SSH-aktivitet. Kontrollér, at træningsperioderne er normalt arbejde og ikke inkluderer forsøg eller laboratorieangreb. Overlappende 300-sekundersvinduer er ikke uafhængige datapunkter. Træning kræver variation i antallet af loginresultater, ikke blot mange gentagne ens logins.
2. Hold andre perioder eller hele scenarier tilbage til validering/test og evaluering af falske positiver og falske negativer. Gem datakildens periode og provenance i rapporten.
3. Brug eventuelt den eksisterende reproducerbare syntetiske labtest til at demonstrere Isolation Forest og regelbaseret evaluering på separate data. Dens metrikker dokumenterer kun laboratoriedata – ikke Pi'ens realtidsdetektionsrate. Installér ikke laboratoriemodellen som produktionsmodel.
4. Når et gennemgået datasæt opfylder både mindstekrav og variation, brug programmets prepare-training eller export-features til en bevidst udvalgt JSON-fil og den eksisterende train-kommando med provenance. Aktivér først modellen i drift efter kontrol og separat accept.

## Read-only variationstest på Pi

Kommandoen viser kun aggregerede antal, ingen IP-adresser eller brugernavne:

~~~bash
sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python - <<'PY'
import sqlite3
from datetime import datetime, timezone

uri = "file:/var/lib/yggdrasil-ids/events.sqlite3?mode=ro"
with sqlite3.connect(uri, uri=True) as db:
    db.execute("PRAGMA query_only=ON")
    outcomes = db.execute(
        "SELECT outcome, COUNT(*) FROM events GROUP BY outcome"
    ).fetchall()
    diversity = db.execute(
        "SELECT COUNT(DISTINCT features), COUNT(*) FROM observations "
        "WHERE state!='late'"
    ).fetchone()
    span = db.execute(
        "SELECT COUNT(DISTINCT source_ip), "
        "COUNT(DISTINCT DATE(timestamp,'unixepoch')), "
        "MIN(timestamp), MAX(timestamp) FROM events"
    ).fetchone()

print("Loginresultater:", dict(outcomes))
print("Unikke feature-vektorer / observationer:", diversity)
print("Forskellige kildeadresser (kun antal):", span[0])
print("Dage med registrering:", span[1])
for label, value in (("Første", span[2]), ("Seneste", span[3])):
    print(label + " hændelse (UTC):",
          datetime.fromtimestamp(value, timezone.utc).isoformat()
          if value is not None else "ingen")
PY
~~~

Antal unikke features og tidsfordeling viser variation, men beviser ikke, at trafikken er normal.

## Screenshot-bilag til rapporten

- ML-A: Screenshot af dashboard med Model ikke trænet og den read-only baseline på 12/80 observationer.
- ML-B: Anonymiseret aggregeret output fra variationstesten; ingen IP-adresser eller rå logs.
- ML-C: Separat syntetisk labrapport og dens testresultater, hvis den køres; skriv tydeligt LAB og ikke live.
- ML-D: Når rigtig model er valideret: modelversion, træningsperiode, prøveantal og hold-out-evaluering. Ikke før faktisk træning.

**Berørte kodefiler:** src/yggdrasil_ids/cli.py (train, prepare-training, export-features, lab), src/yggdrasil_ids/ml.py (minimum, variation, modelartefakt), src/yggdrasil_ids/features.py (seks SSH-features), src/yggdrasil_ids/lab.py (syntetisk hold-out-test).

## Rapportdiskussion – privat server kontra større miljø

Yggdrasil har aktuelt én primær administrator og et meget lavt volumen af
SSH-autentificeringer: 12 events/observationer mod det tekniske minimum 80.
Det er derfor svært at opbygge en *repræsentativ* normalprofil hurtigt.
En virksomhed med eksempelvis 10–20 aktive SSH-brugere **kan** få flere
observationer pr. døgn, men antallet af brugere er ikke i sig selv nok:
mange brugere kan også give mere heterogen normaladfærd, forskellige
arbejdstider og flere legitime sjældne hændelser. Faktisk SSH-brug og
datakvalitet skal måles, ikke antages ud fra virksomhedens størrelse.

De seks nuværende SSH-features afspejler bl.a. fejl/succes, antal
brugernavne, fejlandel og tidspunkt i rullende 300-sekundersvinduer
for en kilde. Tætliggende observationer kan overlappe og er ikke
uafhængige. Derfor giver 80 næsten identiske loginforsøg ikke
samme læringsværdi som varierede gennemgåede normale scenarier.

**Til rapportens diskussion:** Datagrundlag, bias, generaliserbarhed,
falske positiver ved legitim usædvanlig aktivitet og domæneskift
mellem homelab og virksomhedsnet. Skeln metodisk mellem et
implementeret og syntetisk evalueret ML-system og en ML-detektor,
der er valideret og aktiveret i produktion. Den syntetiske
laboratoriemodel må ikke fremstilles som trænet på Yggdrasils
normale SSH-drift. Det er en observeret projektbegrænsning,
ikke et fejlsymptom i den regelbaserede IDS.

## Opdatering fra Pi, 2. november 2026

Den nye aggregerede, read-only audit fandt **15** SSH-hændelser og **15** observationer fordelt på **3 dage**, alle succeser fra én kildeadresse; **15** unikke feature-vektorer og fortsat **ingen live-model**. Det tekniske hul til 80 er nu **65** rækker. De tidligere 12/80 i dette dokument er en *historisk baseline*, ikke den seneste måling.

Et **isoleret** laboratorium blev gennemført på Pi med 312 syntetiske normale træningshændelser, 44 valideringshændelser og 41 sluttesthændelser. Model `ssh-if-16ae0fc3a05948df`; alle checks for datasplit, hash, prædiktions- og confusion-matrix bestod. **Ikke en model af live Yggdrasil-brug**. Se [resultaterne](SPRINT_4_PI_RESULTS.md).
