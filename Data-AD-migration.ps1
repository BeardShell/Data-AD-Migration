# Data AD Migration Tool

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

#Set Initial Variables
$exportDir = 'D:\Migratie\Csv'      #locatie voor de export CSV's
$loggingDir = 'D:\Migratie\Logging' #locatie voor de logging

Function Get-MigrateADGroup {
    #haal oude groepen op
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$Identity,
        $fromCsv
    )
    #$ADGroups = Get-ADGroup 
    
}

Function Export-MigrateADusersToCsv {

}

Function Set-MigrateNTFSRights {

}

Function New-RollbackMigration {
    #draai de migratie terug (functie moet nog uitgedacht worden)
}

Function Write-MigrateLogging {
    #schrijf migratie logging weg, zodat er altijd kan worden nagegaan wat er gebeurt is
}