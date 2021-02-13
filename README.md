# Data-AD-Migration
 Script geschreven ter ondersteuning van Data en AD migraties

MoSCoW Analyse

Must haves:
- AD-groepen ingeven die worden omgezet naar dezelfde groepnamen met Read-Only toevoeging
- Export maken naar CSV van leden in AD-groepen
- Leden van bestaande AD-groep overzetten naar Read-Only AD-groep
- Legen van bestaande AD-groep nádat er een export naar CSV is gemaakt
- NTFS rechten zetten op mappen

Should haves:
- Rollback optie om CSV leden weer terug te zetten in originele groep
- Uitgebreide logging
- Error controle

Could haves:
- Verbose logging
- Commandline parameter settings
- Synopsis

Wanna haves:
- Voorbeeld output van het commando ter controle of de juiste syntax is opgegeven
- Rollback op basis van logging
- Filter opties om AD-groepen in te geven
- CSV import met bestaande groepen die uitgevoerd moeten worden (gefaseerde migratie mogelijk)
- Uitgebreide synopsis