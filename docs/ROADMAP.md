# Roadmap

Projektet udvikles i afgrænsede sprints. En implementeret funktion og en bestået
softwaretest er adskilt fra accepttest på den faktiske server. Planen nedenfor
beskriver den aktuelle status; den er ikke en historik over tidligere releases.

## Sprint 1 · SSH-overvågning

**Status: Implementeret og softwaretestet. Pi-accepttest afventer.**

Leverancen omfatter journalindsamling, fortolkning af SSH-autentificeringer,
konfigurerbare regler, Isolation Forest, SQLite-historik og et privat dansk
webdashboard. Collector og dashboard kører som separate tjenester. Demo,
syntetisk laboratorieforsøg, tests og installationsvejledning følger med.

Før sprintet kan accepteres på målsystemet, skal [Pi-accepttesten](TEST_ON_PI.md)
bekræfte de faktiske logformater, servicekontienes rettigheder, genstart uden
dubletter, backup/restore og målt svartid. Ressourceforbrug og fejl følges over
mindst 24 timers drift. Et tilstrækkeligt normaldatagrundlag skal opbygges før
modellens detektionskvalitet kan vurderes i det konkrete miljø.

[Verifikationen](VERIFICATION.md) beskriver, hvad der allerede er afprøvet,
og hvilke begrænsninger resultaterne har.

## Sprint 2 · Discord-notifikationer

**Status: Planlagt; endnu ikke implementeret.**

Formålet er at modtage udvalgte alarmer på telefonen uden at holde dashboardet
åbent. Den planlagte integration bruger en Discord-webhook til en valgt kanal.

- Konfiguration af webhook og alarmniveau uden hemmeligheder i Git eller logtekst.
- Korte beskeder med hændelsestype, tidspunkt og begrundelse; begrænset deling af
  IP-adresser, brugernavne og rå logs.
- Gruppering og begrænsning af gentagne beskeder samt kontrollerede genforsøg.
- Synlig leveringsstatus; en netværksfejl må ikke stoppe logindsamlingen.
- En særskilt notifierkomponent, så collectorens begrænsede netværksadgang kan
  bevares. Den konkrete proces- og rettighedsmodel fastlægges i sprintet.

Accept kræver både en kontrolleret leveret testbesked og dokumenteret håndtering
af ugyldig webhook, midlertidig netværksfejl og mange gentagne fund. Tests skal
som udgangspunkt bruge en simuleret modtager; rigtige beskeder afprøves i en
udtrykkeligt valgt testkanal.

## Backlog · prioriteres efter de første sprints

| Område | Mulig funktion | Afklaring før implementering |
| --- | --- | --- |
| Netværk og portscanning | Oversigt over observerede forbindelsesforsøg og scanmønstre. | Valg af logkilde, dækning og ratebegrænsning; antal firewallposter er ikke antal bots. |
| Administratorrettigheder | Analyse af sudo-hændelser og usædvanlige privilegerede handlinger. | Hvilke hændelser logges, hvad er forventet administration, og findes egnede normaldata? |
| Filintegritet | Registrering af ændringer i udvalgte vigtige filer. | Filvalg, forventede opdateringer og forskellen mellem ændringsregistrering og forklaring af årsagen. |
| Flere ML-modeller | Isolation Forest på andre meningsfulde aktivitetsfeatures. | Tilstrækkelige data, særskilte features og evaluering mod relevante regler. |
| Daglige og ugentlige oversigter | Samlet historik over alarmer, aktivitet og datakvalitet. | Rapportindhold, dataperiode og eventuel levering til Discord. |

Disse områder har endnu ikke sprintnumre eller lovede leveringsdatoer. Hver
udvidelse skal have et konkret mål, en kendt datakilde og kontrollerbare
acceptkriterier. Et domæne eller en offentlig webapp er ikke en forudsætning
for projektet, og testscenarier kræver ikke åbning af serveren mod internettet.
