# SSH-logning før en kontrolleret accepttest

Denne vedligeholdelsesgren indeholder et særskilt, manuelt driftsscript. Det
ændrer OpenSSH-logningen på den allerede installerede produktionsrelease;
det installerer ikke en ny IDS-version og fremkalder ingen loginforsøg.

## Hvorfor VERBOSE

Den observerede Yggdrasil-konfiguration tillod nøglelogin og havde
`PasswordAuthentication no`, `KbdInteractiveAuthentication no` og
`LogLevel INFO`. OpenSSH kan logge afviste offentlige nøgletilbud på
`VERBOSE`, så de kan mangle i journalen ved `INFO`.

IDS'en analyserer genkendte `Accepted`- og `Failed`-autentificeringsposter fra
betroede OpenSSH-processer. En klientreturkode på 255, en `Invalid user`-linje
eller en forbindelse, der afbrydes før login, er ikke i sig selv en sådan
fejlet autentificering. Den konkrete `Failed publickey`-linje og dens
observation skal derfor kontrolleres efter en nøgleafvisning.

## Den eksplicitte ændring

`deploy/configure_ssh_logging_pi.py` køres som root gennem sudo fra den
eksisterende SSH-session på Yggdrasil. Det kræver den accepterede IDS-releases
fulde SHA og en allerede aktiv Fail2ban-undtagelse for sessionens kildeadresse.
Undtagelsen gælder Fail2ban; IDS'ens registrering, regler og ML fortsætter.

Scriptet kontrollerer den aktive SSH-tjeneste, daemonens kommandolinje og den
effektive konfiguration. Det opretter kun en ny fil:

```text
/etc/ssh/sshd_config.d/00-yggdrasil-ids-logging.conf
```

Indholdet sætter `LogLevel VERBOSE`. Før SSH genindlæses, skal `sshd -t`
godkende konfigurationen, og alle andre effektive indstillinger skal matche
deres tidligere værdier. Hvis validering eller genindlæsning fejler, forsøger
scriptet at fjerne sin egen nye fil og gendanne den tidligere konfiguration.
En eksisterende fil bliver ikke overskrevet.

Behold administrationssessionen og dashboardtunnelen åbne. Et bestået resultat
viser konfigurationskontrol og en vellykket genindlæsning. Det beviser endnu
ikke, at en faktisk nøgleafvisning er logget, analyseret eller har udløst en
regel-/ML-alarm eller Discord-levering. Disse kontroller udføres særskilt.

VERBOSE giver mere journalindhold, herunder nøglefingerprints og
forbindelsesoplysninger. Behandl journalen og IDS-historikken som private
driftsdata. Brug ikke DEBUG-niveauer som erstatning for denne ændring.

OpenSSH-referencer: [sshd_config](https://man.openbsd.org/sshd_config),
[sshd](https://man.openbsd.org/sshd) og
[autentificeringslogning](https://github.com/openssh/openssh-portable/blob/V_10_0_P1/auth.c).
