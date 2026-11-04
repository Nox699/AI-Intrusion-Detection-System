# Installation og opgradering på Yggdrasil

Den samlede installation har SSH-regler og SSH-ML-alarmer, preauth-regler,
TCP-portscanregler, sudo-regler, dashboard og Discord-notifier. Den bruger
ingen særskilt demo-server eller sudo-model.

De pinnede wrappers er målrettet **`vidar` på værten `yggdrasil`** og den kendte
repo-sti `/home/vidar/AI-Intrusion-Detection-System`. De kræver Debian 13,
Python 3.13, systemd og sudo-adgang. De ændrer ikke SSH, Tailscale, sudoers eller
firewallregler. UFW skal allerede logge de relevante blokerede pakker, hvis
portscanreglen skal kunne se dem.

Vælg enten **opgradering af den eksisterende installation** eller **første
installation**. Kør ikke førstegangsinstallationen over en fungerende server.

## Kilde og commit

Brug en gennemgået fuld commit-SHA. Kommandoerne nedenfor indeholder en tydelig
pladsholder; erstat den med den SHA, der er frigivet til installation. De
installerer den fastlåste kilde uden at ændre din arbejdskopis checkout.

Wrapperne henter og kontrollerer `main`. Hvis grenens head
er ændret, stopper en opgradering eller første installation før aktivering.
En grøn CI-kørsel er softwarekontrol; [accepten på Pi](../docs/ACCEPTANCE.md)
er et separat trin.

## Opgradering af den kendte installation

Opgraderingen forventer den verificerede schema5-installation med de eksisterende
collector-, web- og notifierkonti, fungerende journaladgang, aktiv sudo-indsamling
og en indlæselig SSH-model. Overgangen fra den tidligere installation forventer
den dokumenterede SSH-model `ssh-if-7cc1f15288d0c73b`.

Den bevarer konfigurationsprofiler, den tilpassede portscangrænse, modelbytes og
tærskel, aktuel historik, outbox-identitet og notifierens private leveringsstatus.
Den aktiverer SSH-modellens alarmering og den samlede produktionsopsætning, men
træner ikke modellen og fremkalder ingen testangreb eller testbeskeder.

Kør som `vidar` på Pi'en:

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  branch="main"
  sha="INDSAET_GENNEMGAAET_FULD_COMMIT_SHA"

  git fetch --no-tags origin \
    "refs/heads/$branch:refs/remotes/origin/$branch"
  test "$(git rev-parse "origin/$branch")" = "$sha"

  bash <(git show "$sha:deploy/upgrade_pi.sh") "$sha"
)
```

Forløbet kontrollerer den nye release og de faktiske servicekonti før skiftet.
Det stopper de tidligere skrivende roller og sudo-timere koordineret, tager en
konsistent SQLite-backup og kopierer den private sudo-tilstand til den nye
produktionssti. Den nye kilde, fælles konfiguration og canonical units aktiveres
derefter samlet. Kun de gennemgåede gamle kildeoverrides fjernes; uventede lokale
ændringer afvises.

Releaser ligger under `/opt/yggdrasil-ids/releases/<sha>`. Den root-ejede
`current`-reference og CLI-entrypoint vælger samme kilde til de relevante roller.
Det eksisterende virtuelle miljø genbruges efter kontrol mod `requirements.lock`.
Dermed udskiftes afhængigheder ikke tilfældigt under opgraderingen.

Accepten kræver blandt andet frisk collector- og sudo-status, den forventede
SSH-model med aktiverede alarmer, fungerende loginbeskyttede sider og matchende
notifier-identitet. En inaktiv oneshot-service er ikke i sig selv en fejl;
der kontrolleres friskhed af det gemte resultat. Der påstås ingen ny
Discord-levering, når denne opgradering ikke har genereret en ny alarm.

## Første installation

Førstegangsinstallationen afviser eksisterende konfiguration, database,
notifier-tilstand, aktiv release og eksisterende produktionsunits. Den kræver
en **allerede trænet, gennemgået SSH-model** som privat JSON-fil. Repoet
indeholder ingen privat model og fremstiller ikke automatisk et normalt
træningsgrundlag for at opnå en grøn modelstatus.

Installer grundværktøjer og klon repoet, hvis de ikke findes:

```bash
sudo apt update
sudo apt install git python3-venv
git clone https://github.com/Nox699/AI-Intrusion-Detection-System.git \
  /home/vidar/AI-Intrusion-Detection-System
```

Opret først webhookfilen privat. URL'en må ikke stå i en shellkommando,
et screenshot eller Git:

```bash
sudo install -d -o root -g root -m 0755 /etc/yggdrasil-ids
sudo touch /etc/yggdrasil-ids/discord-webhook.url
sudo chown root:root /etc/yggdrasil-ids/discord-webhook.url
sudo chmod 0600 /etc/yggdrasil-ids/discord-webhook.url
sudoedit /etc/yggdrasil-ids/discord-webhook.url
```

Indsæt én gennemgået Discord-webhook-URL i editoren, gem og luk. Den leveres
senere til notifieren som systemd-credential. Installationen viser ikke værdien.

Gennemgå `deploy/config.pi.toml` i den valgte commit. Standardopsætningen
aktiverer netværk og sudo; profilfelterne for forventede SSH-brugere og
kildeadresser er tomme. En tom profil slår den tilsvarende kontrol af vellykkede
logins fra. Gennemgå derfor din normale SSH-profil som en del af accepten;
Tailscale-adgang beviser ikke i sig selv en persons identitet.

Kør derefter med stien til den gennemgåede modelfil. Begge værdier nedenfor er
pladsholdere og skal erstattes:

```bash
(
  set -euo pipefail
  cd /home/vidar/AI-Intrusion-Detection-System
  branch="main"
  sha="INDSAET_GENNEMGAAET_FULD_COMMIT_SHA"
  model="/absolut/sti/til/gennemgaaet-ssh-model.json"

  git fetch --no-tags origin \
    "refs/heads/$branch:refs/remotes/origin/$branch"
  test "$(git rev-parse "origin/$branch")" = "$sha"

  bash <(git show "$sha:deploy/install_pi.sh") "$sha" "$model"
)
```

Installationen opretter de adskilte servicekonti, et virtuelt miljø med låste
runtime-afhængigheder, den private modelkopi, database og units. Den spørger
interaktivt to gange efter en ny dashboardadgangskode. Kun på en helt ny
installation initialiseres notifierens leveringsidentitet. Sudo-integrationen
armeres eksplicit, før den samlede drift starter.

SSH-collectorens første historikvindue kan indeholde op til konfigurationens
24 timer med virkelige journalhændelser. De kan give ægte regel- eller ML-fund
og Discord-beskeder, selv om installationsscriptet ikke fremkalder testangreb.
En softwaremæssigt indlæst model er endnu ikke et bevis for ny live SSH-scoring
eller faktisk ML-til-Discord-levering.

## Dashboard og kontrol

Web lytter på `127.0.0.1:8765`. Opret SSH-tunnelen fra laptoppen som beskrevet
i [README](../README.md), og brug din nye eller bevarede adgangskode.
Der åbnes ingen ekstra offentlig webport.

Følg [ACCEPTANCE.md](../docs/ACCEPTANCE.md), og gem den installerede commit,
SSH-modelversion og de konkrete resultater. Service- og journalfejlsøgning
findes i [OPERATIONS.md](../docs/OPERATIONS.md). Automatiserede kontroller er
beskrevet i [TESTING.md](../docs/TESTING.md).

## Fejl og rollback ved opgradering

Ved fejl efter runtime-skiftet forsøger opgraderingen at gendanne tidligere
kildevalg, konfiguration, units og tidligere tjenestetilstande. Den overskriver
aldrig den aktuelle produktionsdatabase med en gammel backup og nulstiller
ikke notifierens leveringshistorik. Data, der blev registreret under forsøget,
skal bevares. Private backups ligger under
`/var/backups/yggdrasil-ids/production-before-<sha>`.

Ved en senere, bevidst rollback bruges den samme commit som den aktive release
og dens eksisterende backup:

```bash
bash <(git show "$sha:deploy/upgrade_pi.sh") "$sha" rollback
```

Rollback kræver matchende aktiv release og backup. Det er ikke en generel
databasegendannelse eller en afinstallation af en ny førstegangsinstallation.
Hvis scriptet skriver STOP eller RECOVERY, læses den konkrete fejl før flere
opgraderingsforsøg. Slet ikke backups eller leveringsstatus for at få en
ny kørsel til at fortsætte.
