# Data-AD-Migration
 Script geschreven ter ondersteuning van Data en AD migraties
 
Functie uitleg
Set-MigrationBasics: Creeër mappenstructuur als deze niet bestaat. Nuttig om als eerste uit te voeren zodat alle overige functies werken.
Initialize-Migration: Geef een SearchBase op van Active Directory en maak voor elke rechtengroep een CSV aan met alle members.
Get-PathWithSecurityGroup: Geef een (DFS)pad op. Vervolgens worden alle niet erfbare rechten uitgelezen en er nieuwe READ groepen aangemaakt. 
New-ADMigrationGroups: Creeër nieuwe AD groepen gebaseerd op de data uit Get-PathWithSecurityGroup.
Set-MigrateNTFSRights: Geef de nieuwe AD groepen ReadAndExecute rechten op de bijbehorende DFS paden en alle onderliggende mappen en bestanden.
Get-MigrationPreviousRights: Helpdesk functie. Als users klagen dat ze rechten hadden kan er worden nagegaan of deze rechten daadwerkelijk uitgedeeld waren.
New-MigrateReadGroup: NIET zelf uitvoerbaar, is een hulpfunctie voor Get-PathWithSecurityGroup
Write-MigrateLogging: NIET zelf uitvoerbaar, is een hulpfunctie voor alle andere functies t.b.v. logging

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
