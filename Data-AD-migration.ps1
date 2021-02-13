# Data AD Migration Tool

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

#Set Initial Variables
$workingDir = "D:\Migratie"         #Basis directory. LET OP: Geen \ op het einde toevoegen!
$ADSearchBase = "OU=Data Toegang,OU=Groepen,OU=Organisatie Nieuw,DC=lv,DC=leidschendamvoorburg,DC=nl"

#VANAF HIER GEEN AANPASSINGEN MAKEN AAN HET SCRIPT#

$csvDir = "$($workingDir)\Csv\"      #locatie voor de export CSV's
$logDir = "$($workingDir)\Logging\"  #locatie voor de logging
$xmlDir = "$($workingDir)\Xml\"      #locatie voor XML bestanden

Function Initialize-Migration {
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string]$ADSearchBase
    )
    try {
        $ADGroups = Get-ADGroup -Filter * -SearchBase $ADSearchBase
        foreach ($ADGroup in $ADGroups) {
            $CSV = ($ADGroup.Name) + ".csv"
            $ADGroupMembers = Get-ADGroupMember -Identity $ADGroup | ForEach-Object {
                [pscustomobject]@{
                    GroupName = $ADGroup.Name
                    Name = $_.SamAccountName
                }
            }
            $ADGroupMembers | Export-Csv -Path "$($csvDir)$($CSV)" -Delimiter ";"
        }
    } Catch {
        Write-Error $error.Count
    }
}

Function Get-MigrateADGroup {
    #haal oude groepen op
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,Mandatory=$false)]
        [string[]]$Name,
        $fromCsv
    )
    try {
        $ADGroups = Get-ADGroup -Filter {Name -like $name}
    }
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