# Sprint 4 – SSH preauth og fremtidig ML-datadækning

**Status: Read-only parseraudit på GitHub. Ingen kode er installeret på Yggdrasil; eksisterende hybridmodel `ssh-if-7cc1f15288d0c73b` kører fortsat i shadow-mode uændret.**

## Observation på rigtig Pi, 2. november 2026

To særskilte, kontrollerede SSH-forsøg med ugyldige Ed25519-testnøgler gav ingen nye `events` med `outcome='failure'`, selvom OpenSSH svarede på port 22. Senere **read-only journald-analyse** fra collectorens privilegerede OpenSSH-kilder fandt:

| Logkategori | Poster i undersøgelsesperioden |
| --- | ---: |
| `Accepted` | 4 |
| `Authenticating user / preauth` | 1 |
| `Closed - invalid user` | 1 |
| `Invalid user` | 1 |
| Øvrige SSH-meddelelser | 6 |
| Journalposter med vores markerede ugyldige testbruger | **2** |

Antallet er *journalmeddelelser*, ikke antallet af angreb eller loginforsøg. De to testrelaterede linjer kan være **ét SSH-forbindelsesforsøg**, fordi OpenSSH både kan logge `Invalid user` og efterfølgende `Connection closed by invalid user`. Det må ikke tælles som to forsøg før korrelation på kilde, kildeport, boot og tid.

### Hvad virker – og hvad mangler?

- **Fungerer:** Et rigtigt succesfuldt SSH-login blev verificeret scoret af den eksperimentelle hybride Isolation Forest på Pi den 2. november kl. 17:47:48 CET: score **0,4775**, tærskel **0,6164**, `Inden for grænsen`, modelstatus `ready/shadow`, ingen ML-fund.
- **Begrænsning:** Den nuværende seks-dimensionelle SSH-ML-featurevektor skabes kun for accepterede `Accepted` eller `Failed`-autentificeringer. `Invalid user` og mange `[preauth]`-afvisninger er ikke sådanne hændelser, og derfor opstår ingen ML-score for disse forsøg.
- **Allerede dækket andetsteds:** Den eksisterende regelbaserede preauth-detektor og dashboard genkender *to* `Connection closed/reset by authenticating user ... [preauth]`-formater. Det er **ikke** en ML-detektor og dækker ikke `Connection closed by invalid user`.
- **Skelnen:** En publickey-afvisning er ikke nødvendigvis en `Failed publickey`-loglinje på denne OpenSSH-konfiguration. Et preauth-disconnect alene er ikke dokumentation for et angreb.

## Fase A – bekræft logformater uden at ændre Pi (implementeret)

`deploy/sprint4_preauth_signal_audit.py` læser journalen som `yggdrasil-worker`, bruger betroet `_COMM` og `_UID=0`, og tæller kun groft fire kendte mønstre:

- `Invalid user <username> from <address> port <port>`
- `Connection closed/reset by invalid user <username> <address> port <port> [preauth]`
- `Connection closed/reset by authenticating user <username> <address> port <port> [preauth]`
- `Disconnected from invalid user <username> <address> port <port> [preauth]`

IP'er, brugernavne, kildeporte og rå meddelelser forbliver **kun i processens hukommelse**. De viste data er alene kategorier og antal. Audit korrelerer kandidatlinjer med (`_BOOT_ID`, kilde-IP, kildeport), så samme forbindelse ikke fejlagtigt tælles som flere forskellige forbindelser. Genbrug af samme source port betyder, at dette kun er en **approksimation**, ikke en præcis sessionsoptælling. Testbrugeren er en generisk laboratoriemarkør; navnet vises ikke.

En særskilt sammenligning viser, hvor mange rækker den **eksisterende** preauth-parser allerede genkender. Scriptet læser kun historik, ikke SQLite eller credentials; ingen systemd-/UFW-/Fail2ban-ændringer, modeltræning, databaseopdatering eller Discord-beskeder.

**Kør først efter bestået CI og med en pinnet, godkendt SHA:**

~~~bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_GRON_SHA_HER'
  git fetch --no-tags origin sprint-4/preauth-ml-coverage
  test "$(git rev-parse origin/sprint-4/preauth-ml-coverage)" = "$sha"
  git show "$sha:deploy/sprint4_preauth_signal_audit.py" |
    sudo -u yggdrasil-worker /opt/yggdrasil-ids/venv/bin/python -       --since "2026-11-02 15:00:00"
)
~~~

## Fase B – kommende ML-udvidelse (IKKE implementeret)

For at få Isolation Forest til at registrere SSH-forsøg, der afvises før egentlig autentificering, bør vi opbygge **et separat, versionsstyret preauth-featuregrundlag**, frem for at score fire nye features med den allerede trænede seks-feature SSH-model.

Foreløbig featureidé, grupperet pr. kilde i rullende vinduer på 300 sekunder:

1. Antal **forskellige preauth-forbindelseskandidater** (korrelerede source-port-nøgler).
2. Antal `Invalid user`-meddelelser og antal forskellige ugyldige brugernavne (kun tal til ML, ikke identiteter).
3. Antal preauth-afbrydelser og forhold mellem disse og øvrige forbindelsessignaler.
4. Fordeling af preauth-hændelser i tidsintervaller.

Det er **ikke** meningsfuldt automatisk at antage, at preauth-testforsøg er normale træningsobservationer. For en eksperimentel preauth-Isolation-Forest skal vi have særskilte **syntetiske normale** træningsforløb, selvstændige mærkede hold-out-testforløb og efterfølgende kontrolleret shadow-scoring på Pi. Det er en ny model/featureversion og skal evalueres separat mod relevante regler. De tidligere 312+12 træningsrækker kan ikke bruges direkte uden ombygning og en ny dokumenteret datasplit.

Ved senere produktion skal vi holde testangreb ude af normaltræningen, bevare eksisterende SSH/UFW/Discord, samt aktivere ny scoring uden ML-beskeder, indtil falske positiver er undersøgt. Ingen ny model eller UFW-/Fail2ban-ændring følger automatisk af fase A.

## Eksamen: observation og metode

Dette er dokumentation for **en datakildebegrænsning**: journalisering, parserdækning og faktisk ML-observation er tre forskellige ting. Manglende `Failed`-rækker betyder ikke, at OpenSSH har ignoreret forsøget. Det nuværende hybrid-ML-system er allerede teknisk testet med én normal live-score; en preauth-ML-model er derimod endnu ikke udviklet eller valideret på live Pi. Det skal skelnes klart i rapporten.

## Fase A – verificeret på Pi, 2. november 2026

Den versionspinnede read-only audit fra commit `f0c7047a7d15e8a4015b90a7c8fcbdb893d0d224` blev gennemført under eksisterende `yggdrasil-worker` uden installation, modeltræning eller serviceændring.

| Faktisk måling | Antal |
| --- | ---: |
| Gennemgåede/troværdige root-OpenSSH-poster | 13 / 13 |
| Mulige preauth-signalposter | **3** |
| `invalid_user_notice` | 1 |
| `invalid_user_disconnect` | 1 |
| `authenticating_user_disconnect` | 1 |
| `invalid_user_disconnected` | 0 |
| Approksimerede forskellige forbindelse-nøgler | **2** |
| Testrelaterede logposter | **2** |
| Approksimerede forbindelser fra testmarkør | **1** |
| Genkendt af gammel preauth-parser | 1 |
| Betroede poster uden match til disse fire kandidattyper | 10 |
| Malformed eller untrusted poster | 0 |

**Konklusion:** SSH har registreret de to journalposter for invalid-user-testen, men de ser ud til at tilhøre **samme forbindelse**. Den eksisterende `Accepted/Failed`-model modtager ingen observation for testen. Eksisterende preauth-parser genkender kun én af de tre kandidatposter. Der er således et faktisk **observabilitets-/featuredækningshul**, ikke dokumenteret fravær af angreb eller påvist svigt i den trænede SSH-Isolation-Forest. Realdata (2 forbindelser) er ikke et selvstændigt tilstrækkeligt normaltræningsgrundlag for en ny preauth-model. Ingen private kilder/identiteter eller loglinjer er uploadet.


## Fase B – isoleret preauth-Isolation-Forest-prototype (softwareudviklet)

Vi har nu tilføjet en **separat** `preauth-isolation-forest-v1`-model og et
reproducerbart **syntetisk** preauth-laboratorium på udviklingsbranchen. Det er
**ikke** en live installation, og den tidligere hybride SSH-model i shadow-mode
bevares uændret.

Det nye featureskema består af **syv** tal pr. korreleret
preauth-forbindelseskandidat:

| Preauth-feature | Hvad måles? |
| --- | --- |
| `connections_300s` | Antal forbindelseskandidater fra samme kilde i fem minutter |
| `invalid_users_300s` | Antal kandidater med ugyldig bruger |
| `unique_usernames_300s` | Antal forskellige brugernavne, **ikke** navnene selv |
| `disconnects_300s` | Antal kandidater med observeret afbrydelse |
| `invalid_ratio_300s` | Andel kandidater med ugyldig bruger |
| `hour_sin`, `hour_cos` | Tid på døgnet kodet som to cykliske tal |

Journalposter fra samme `_BOOT_ID`, kilde-IP og kildeport korreleres før
featureberegning, med et afgrænset 120-sekunders sammenfletningsvindue.
Det betyder, at to linjer for ét `Invalid user`-forsøg ikke udløser to
ML-observationer i laboratoriet. Det er en *approksimeret*
forbindelseskandidat, ikke dokumenteret fuldstændig netværksforbindelse.
IP og brugernavn bruges **kun til korrelation** og indgår ikke numerisk
i modelvektoren.

### Kontrolleret træning og hold-out-evaluering

`deploy/sprint4_preauth_ml_lab.py` genererer normal- og testsessioner med
dokumentations-IP'er. Syntetiske **normale** forløb omfatter få forventede
preauth-disconnects, sporadiske stavefejl i brugernavne og godkendt
vedligeholdelsesaktivitet. Angrebslignende testforløb omfatter gentagen
ugyldig bruger, mange forskellige ugyldige brugernavne og usædvanligt
mange afbrud.

**Kun train-splittet** (321 normale forbindelseskandidater med fast seed=42)
bruges til modeltræning. Validation og test har separate
tidsperioder med **mere end 600 sekunders afstand**, separate
scenarielabels i `labels.json`, og inputfiler verificeres med SHA-256.
Scenario-hensigt indgår ikke i features. Resultater opgøres i
konfusionsmatricer og precision, recall og falsk positiv-rate
**på hændelsesniveau i syntetiske scenarier**, med sammenligning mod
på forhånd valgte regler.

Den nye `PreauthIsolationForest` har **sit eget faste syv-feature-format**,
`preauth-if-...`-modelversions-id og JSON-fingeraftryk. Den kan ikke
udgives som en model med den tidligere `ssh-if-...`-featurestruktur.
Ingen pickle eller eksekverbar deserialisering. Alle modelfiler
oprettes privat og importeres ikke af den kørende collector.

### Lokal kørsel på Pi – først efter bestået CI

Den nye `deploy/sprint4_run_preauth_ml_lab.sh` henter source **pinnet på
godkendt SHA**, pakker den i en midlertidig mappe og benytter Pi'ens
allerede installerede scikit-learn via en ekstra `PYTHONPATH` –
**uden at opgradere pakken, stoppe services, læse SQLite eller ændre model**.

~~~bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_GRON_SHA_HER'
  git fetch --no-tags origin sprint-4/preauth-ml-coverage
  test "$(git rev-parse origin/sprint-4/preauth-ml-coverage)" = "$sha"
  script="$(mktemp)"
  trap 'rm -f "$script"' EXIT
  git show "$sha:deploy/sprint4_run_preauth_ml_lab.sh" > "$script"
  bash -n "$script"
  bash "$script" "$sha"
)
~~~

Kørslen opretter et **nyt** privat laboratorium under
`~/yggdrasil-preauth-ml-private/preauth-if-*` og viser kun en
aggregeret evaluering i terminalen. Alle tre aktive IDS-tjenester
verificeres før og efter; ingen SSH-forbindelser genereres.
Gem outputtet lokalt og del kun anonymiserede aggregater.

**Vigtig begrænsning:** Modellen er stadig syntetisk trænet, fordi den
faktiske Pi-audit kun fandt to preauth-forbindelseskandidater.
Denne prototype er et design- og evalueringsforsøg, ikke
dokumenteret sikkerhedsdetektion på rigtige angreb. Live-scoring af
preauth kræver separat parser-/storage-/dashboard-udvidelse,
modelevaluering og backup/rollback. Den eksisterende
`ssh-if-7cc1f15288d0c73b` fortsætter i shadow-mode indtil da.

## Fase B – faktisk Pi-laboratorietest af preauth-Isolation-Forest

**2. november 2026, verificeret på Yggdrasil:** Pi-ejer kørte det isolerede syntetiske preauth-ML-laboratorium fra kildecommit `79424449be2274bc2ac04cb8f95fbc579c13e1e5`, og alle slutkontroller bestod. Modellen `preauth-if-c117b4177053846a` blev trænet på **321 særskilte syntetiske normale preauth-forbindelseskandidater**, med en modelgrænse på **0,6570063583**. Der blev ikke læst live-SSH-logs, ændret produktionsdatabasen eller installeret en ny live preauth-model; collector, web og notifier blev bekræftet aktive før og efter.

| Datasplit | Metode | TP | FP | TN | FN | Precision | Recall | FP-rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validering (54 kandidater) | Isolation Forest | 15 | 0 | 16 | 23 | 100,0 % | 39,5 % | 0,0 % |
| Validering (54 kandidater) | Regler | 22 | 0 | 16 | 16 | 100,0 % | 57,9 % | 0,0 % |
| Sluttest (49 kandidater) | Isolation Forest | 17 | 0 | 14 | 18 | 100,0 % | 48,6 % | 0,0 % |
| Sluttest (49 kandidater) | Regler | 19 | 0 | 14 | 16 | 100,0 % | 54,3 % | 0,0 % |

**Testgrundlag:** Sluttestens 49 korrelerede forbindelseskandidater er **35 mærket simuleret mistænkelige og 14 mærket normale**, ikke 49 uafhængige angreb. Valideringens 54 er 38 mistænkelige og 16 normale. Tidlige observationer i samme scenario kan være under begge metoders tærskel, og samme scenarios hændelser deler kilde og rullende tidsvindue. Precision=100 % og FP-rate=0 % gælder kun de konstruerede sæt med hhv. 16/14 normale kandidater; ingen virkelighedsbaseret rate kan udledes.

**Faglig konklusion:** De fastsatte regler klarede sig **bedre end Isolation Forest** på begge splits i dette konkrete, konstruerede laboratorium (validerings-recall 57,9 vs. 39,5 %; sluttest-recall 54,3 vs. 48,6 %). Modellen er teknisk trænet, versionsbestemt og evalueret, men **ikke tilstrækkeligt god til at blive fremstillet som bedre end de nuværende regler**. Vi må ikke optimere mod sluttestens labels; i stedet skal vi diagnosticere på de allerede gemte scenarie-opdelinger og kun evt. justere features eller model ud fra trænings- og valideringsdata før en helt ny låst sluttest.

**Private labfiler** blev gemt under `~/yggdrasil-preauth-ml-private/preauth-if-*/` på Pi. Ingen modelbyte, journalposter, kilde-IP'er eller private identiteter er lagt i GitHub. Dette afsnit indeholder kun de af brugeren bekræftede aggregerede evalueringstal.

## Scenarievis analyse af den afsluttede preauth-test – 2. november 2026

Brugeren gennemgik **den allerede låste, uændrede** `report.json` fra Pi'ens syntetiske laboratorium. Tabellen viser **TP pr. mærket mistænkelig forbindelse** (ikke uafhængige angreb eller antal Discord-alarmer):

| Scenarie | Validering: ML / regel (ud af N) | Sluttest: ML / regel (ud af N) |
| --- | --- | --- |
| `invalid_user_spray` | 6 / 7 (N=10) | **8 / 6** (N=9) |
| `invalid_user_burst` | 9 / 9 (N=13) | **9 / 8** (N=12) |
| `preauth_disconnect_surge` | **0 / 6** (N=15) | **0 / 5** (N=14) |

De fire mærkede normale scenarier (`short_legitimate`, `legitimate_typo`, `routine_maintenance` og `new_legitimate_source`) gav **ingen falske positive for nogen af metoderne**: validering 16 normale forbindelseskandidater, sluttest 14. Dette er meget lidt normaldata og siger intet om virkelig produktions-FPR.

**Den afgørende fejlkategori:** Isolation Forest overså **samtlige 29** mærkede `preauth_disconnect_surge`-kandidater på tværs af validering og sluttest. Det udgør 15 af valideringens 23 ML-falsk-negative og 14 af sluttestens 18 ML-falsk-negative. Ser man *udelukkende* på de øvrige to typer i den syntetiske sluttest, opdagede ML **17/21 (81,0 %)** og reglerne **14/21 (66,7 %)**; dette er en efterfølgende *deskriptiv* delmængdeanalyse af den allerede anvendte sluttest, **ikke** en ny uafhængig benchmark eller grundlag for tærskeljustering. På valideringens tilsvarende delmængde er ML **15/23 (65,2 %)** og regler **16/23 (69,6 %)**.

**Teknisk hypotese baseret på kildekoden:** Laboratoriets generator udsender en `Connection closed ... [preauth]`-meddelelse for **hver** syntetisk normal og mistænkelig forbindelseskandidat. Korrelationen registrerer derfor `disconnected=True` for alle genererede forbindelser. Følgelig er `disconnects_300s` og `connections_300s` altid identiske i disse forløb. Denne feature er altså redundant i netop laboratoriets data; `preauth_disconnect_surge` kan ikke skelnes fra legitim masseafvisning via disconnect-**typen** alene, kun via dens antal/hyppighed eller timing. Isolation Forest har ikke en iboende garanti for at markere værdier, der blot er større end træningsmaksimum. Dette **kan** forklare svagheden, men årsagen til de enkelte scores kræver en særskilt analyse af scorefordeling og træningsvariation.

**Fortolkningsrisiko:** Et stort antal afbrudte preauth-forbindelser er ikke automatisk et angreb. Testscenariets `simulated_suspicious`-label er en antagelse i den konstruerede case, ikke et sikkerhedsfaktum. Begge metoder bør derfor evalueres på mere varierede, uafhængige normale forbindelsesmønstre (fx vedligeholdelse, afbrudt net og legitime automatiserede reconnects) før en reel alarm besluttes.

**Næste metodisk forsvarlige udviklingsspor:** Bevar den aktuelle modelversion og de offentliggjorte testresultater. Udvikl en **regel+ML kombination i et adskilt, offline forsøg** med på forhånd valgte regler og logisk OR, og mål både *forbindelsesniveau* (confusion matrix) og *scenarieniveau* (om der nogensinde kom et fund, samt antal forbindelser til første fund). Undersøg redundant feature- og træningsdiversitet på et nyt syntetisk normaldesign uden at kigge efter den gamle sluttests bedste tærskel. Brug et **helt nyt uafhængigt sluttestsæt**, hvis model eller alarmgrænser justeres. Ikke installeret på Pi; eksisterende SSH-Isolation-Forest og Discord-alarmregler uændrede.

## Låst hybrid-analyse på eksisterende syntetiske resultater

`deploy/sprint4_preauth_hybrid_diagnostics.py` er et **rent read-only analyseværktøj** til det **allerede genererede** syntetiske laboratoriemateriale. Det indlæser originalt `manifest.json` (SHA-256), `labels.json`, `report.json` og den hash-verificerede private `preauth-lab-model.json`, men træner **ikke igen** og ændrer **ikke** det eksisterende testdatasæt, modellens threshold, tjenesternes indstillinger eller nogen produktionsdatabase.

Analysen genberegner de originale ML- og regelklassifikationer og **afviser kørsel**, hvis deres TP/FP/TN/FN eller antal korrelerede forbindelser afviger fra den tidligere gemte rapport. Dernæst vises en **retrospektiv** logisk OR-kombination af AI og regler med både confusion matrix og markering af **første fund i hvert scenarie** (1-baseret forbindelsesnummer). Den tæller også, hvor ofte `disconnects_300s == connections_300s` for at kontrollere redundant feature i dette specifikke syntetiske design.

Den kombinerede tilgang er **valgt efter at den gamle sluttest var set**: Selv hvis dens tal er bedre, er det altså **ikke en ny uafhængig performance-evaluering**. Vi må beskrive resultatet som et retrospektivt diagnostisk eksperiment og afprøve en eventuel fremtidig model-/regelkombination på nye, låste uafhængige scenarier med flere typer legitim reconnect-trafik. Der er ingen produktionsaktivering eller Discord-effekt.

Kør kun lokalt på Pi efter CI-kontrol af den valgte commit-SHA og med de allerede eksisterende private syntetiske labfiler:

~~~bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  sha='INDSAET_GODKENDT_SHA_HER'
  git fetch --no-tags origin sprint-4/preauth-ml-coverage
  test "$(git rev-parse origin/sprint-4/preauth-ml-coverage)" = "$sha"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git archive "$sha" src deploy/sprint4_preauth_signal_audit.py \
    deploy/sprint4_preauth_ml_lab.py \
    deploy/sprint4_preauth_hybrid_diagnostics.py | tar -xf - -C "$tmp"
  PYTHONPATH="$tmp/src:$tmp/deploy" \
    /opt/yggdrasil-ids/venv/bin/python \
    "$tmp/deploy/sprint4_preauth_hybrid_diagnostics.py" \
    "$HOME/yggdrasil-preauth-ml-private/preauth-if-jhAFiK8r"
)
~~~

Kun syntetiske scenarienavne og aggregerede resultatmål udskrives. Den sidste labmappe er brugerens allerede eksisterende private laboratorieforsøg; hele mappen eller modellen må ikke uploades til et offentligt repository.

## Retrospektiv hybridanalyse og stresstest – Yggdrasil, 2. november 2026

**Verificeret laboratoriekørsel, ikke produktionsdetektion.** Brugeren kørte
den versionspinnede, skrivebeskyttede kode fra commit
`34d2478cfa878c05631340f3fa55fd09a200deb5` på Pi'en. Den eksisterende
separate preauth-model `preauth-if-c117b4177053846a` blev genbrugt;
hverken træningsrækker, modelgrænse, produktionsdatabase, systemd-tjenester,
UFW, Discord eller live SSH-skyggemodellen blev ændret. GitHub CI for den
pinnede commit er godkendt på Python 3.11 og 3.13.

### 1. Hybrid på oprindelige scenarier

`deploy/sprint4_preauth_hybrid_diagnostics.py` kombinerede eksisterende
klassifikationer med retrospektiv **logisk OR**: et fund, hvis enten regler
eller ML markerer forbindelseskandidaten. Den tidligere sluttest er allerede
inspiceret og kan ikke behandles som uset.

| Datasplit | Metode | TP | FP | TN | FN | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Validering (54 kandidater) | ML | 15 | 0 | 16 | 23 | 39,5 % |
| Validering (54 kandidater) | Regler | 22 | 0 | 16 | 16 | 57,9 % |
| Validering (54 kandidater) | OR-hybrid | 22 | 0 | 16 | 16 | 57,9 % |
| Tidligere sluttest (49 kandidater) | ML | 17 | 0 | 14 | 18 | 48,6 % |
| Tidligere sluttest (49 kandidater) | Regler | 19 | 0 | 14 | 16 | 54,3 % |
| Tidligere sluttest (49 kandidater) | OR-hybrid | 22 | 0 | 14 | 13 | 62,9 % |

ML markerede spray og burst allerede ved første forbindelse i den gamle
sluttest, men først ved femte i valideringen; den missede helt
`preauth_disconnect_surge`. De oprindelige scenarier indeholdt for hver
korreleret kandidat en afbrydelseslinje, hvorfor
`disconnects_300s == connections_300s` for alle 49/54 kandidatvektorer.

### 2. Ændring af kun tidspunkt

`deploy/sprint4_preauth_clock_sensitivity.py` roterede
`hour_sin`/`hour_cos` med 0, 6, 12 og 18 timer uden at ændre de øvrige
fem features, modellen eller grænsen. Valideringens ML-TP ændrede sig fra
15/38 ved 0 timer til 20/38 ved +6 timer, med **2 falske positiver**
mod nul i originalen. Det demonstrerer modelafhængighed af
tidspunktet, ikke tidsstempler fra et faktisk angreb. Samme sæt og
tidligere sete labels blev anvendt; der er ingen ny uafhængig sluttest.

### 3. Supplerende syntetisk robusthedsaudit

`deploy/sprint4_preauth_robustness_audit.py` genererede **11 foruddefinerede
scenarier**, gentaget ved **00, 06, 12 og 18 UTC**. Det gav 448
korrelerede forbindelseskandidater i alt: 172 kunstigt mærket normale
og 276 kunstigt mærket mistænkelige. Dette er **44 scenarieafviklinger
med indbyrdes afhængige observationer**, ikke 448 uafhængige personer,
angreb eller forbindelsesepisoder i rigtig drift. De samlede resultater
er vægtet efter antal kandidater i hvert konstrueret scenarie:

| Metode | TP | FP | TN | FN | Precision | Recall | FP-rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Isoleret preauth-Isolation Forest | 148 | 15 | 157 | 128 | 90,8 % | 53,6 % | 8,7 % |
| Offline-sammenligningsregler | 120 | 24 | 148 | 156 | 83,3 % | 43,5 % | 14,0 % |
| Retrospektiv OR-hybrid | **179** | **35** | 137 | 97 | 83,6 % | **64,9 %** | **20,3 %** |

**Præcision og recall er betinget af denne kunstige klassefordeling og
scenariets antagne hensigt.** Disse tal beskriver kun
de syntetiske labels og er ikke målinger af den kørende IDS'
real-world performance. Reglerne her er en selvstændig offline-komparator;
de er ikke i sig selv en ny produktionsinstallation.

**Konkrete fejlkategorier på tværs af fire tidsafviklinger:**

- Normal `benign_typo_recovery`: **9 ML-FP**, ingen regel-FP.
- Normal `benign_connection_retry_storm`: **20 regel-FP**, ingen ML-FP.
- Normal `benign_repeated_username_typo`: **6 ML-FP**, **4 regel-FP**;
  OR-kombinationen giver 6 FP.
- Mistænkelig `simulated_low_rate_invalid`: **20/32 ML-TP** og
  **0/32 regel-TP**. Dette er kun konstrueret adfærd, ikke bevis på
  reel 'low-and-slow'-detektion.
- Mistænkelig `simulated_preauth_disconnect_surge`: **0/56 ML-TP**
  og **20/56 regel-TP**.
- Mistænkelig `simulated_missing_disconnect_lines`: en isoleret
  `Invalid user`-linje er en kandidatobservation, ikke en
  dokumenteret gennemført SSH-forbindelse eller bevist angreb.

**Lige features, modsat antaget hensigt:** I alle fire tidsafviklinger
har `benign_connection_retry_storm` og
`simulated_preauth_disconnect_surge` **præcis identiske syv-featurevektorer**
pr. tilsvarende forbindelseskandidat. Førstnævnte er mærket normal,
sidstnævnte simuleret mistænkelig. Ingen deterministisk klassifikator
med kun disse input kan skelne de to hensigter. Reglen markerer i begge
forløb fra forbindelse 10, og OR-hybriden arver både detektionsfordelen
og den uundgåelige fejlklassifikation i den konstruerede normale case.
Et højt antal preauth-disconnects er derfor ikke i sig selv angrebsbevis.

**Tidspåvirkning i robusthedsauditen:** ML-TP ud af 69 mærket mistænkelige
kandidater varierede fra **20 kl. 12 UTC** til **52 kl. 18 UTC**, mens de
samme scenarietyper, tidsmellemrum og antal indgik. Samtidigt varierede
ML-FP fra 2 til 6 ud af 43 mærket normale kandidater. Det styrker
behovet for at teste repræsentative tider og vurdere, om tidsfeatures
bidrager meningsfuldt frem for at reproducere syntetiske artefakter.

### 4. Beslutning og næste gate

1. **Bevar** `preauth-if-c117b4177053846a` som dokumenteret
   *offline-eksperiment*. Aktiver ikke preauth-Isolation Forest eller
   OR-hybrid i produktion på baggrund af disse undersøgelser.
2. Bevar den **separat installerede SSH-hybridmodel**
   `ssh-if-7cc1f15288d0c73b` i shadow-mode. Denne model har
   et andet featureskema og må ikke forveksles med preauth-prototypen.
3. Tilføj ikke nye normaltræningsdata eller ændr tærskler efter at have
   set disse tests og kald derefter den gamle test 'uset'.
   Eventuelle nye feature-/modelversioner skal designes på et tydeligt
   udviklingsgrundlag og først bedømmes på nye, låste scenarier.
4. For produktionsaccept mangler repræsentativt normalmateriale fra
   rigtige SSH-journalhændelser, sikkerhedsmæssigt forsvarlige labels
   og en separat, kontrolleret shadow-/rollback-procedure.
   Den tidligere Pi-audit fandt kun **to** preauth-forbindelseskandidater.

**Konklusion til eksamen:** Hybrid OR øgede recall i den udvidede
syntetiske stressprøve, men øgede samtidig andelen af falske positiver;
tidsfeatures og tvetydige disconnect-signaler er observerede
begrænsninger. Resultatet er en eksperimentel sammenligning, ikke
påvist forbedret intrusionsdetektion i virkelig drift.
