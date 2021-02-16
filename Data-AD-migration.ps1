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
    BEGIN {
        try {
            Write-MigrateLogging -LogMessage "Initialize-Migration() started with SearchBase $($ADSearchBase)"
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
                Write-Verbose "AD groep leden van $($ADGroup.Name): opgeslagen in $($csvDir)$($CSV)"
                Write-MigrateLogging -LogMessage "AD groep leden van $($ADGroup.Name): opgeslagen in $($csvDir)$($CSV)"
            }
        } Catch {
            Write-Error $error.Message
        } Finally {
            Write-Output "Initialize-Migration() executed succesfully. See logging for full details"
            Write-MigrateLogging -LogMessage "Initialize-Migration() executed succesfully"
        }
    }
}

Function foo {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$false,Mandatory=$true)]
        [string]$Path,
        [boolean]$Recurse=$true,
        [boolean]$Directory=$true,
        [int]$Depth=1
    )
    $folders = Get-ChildItem -Path $Path -Recurse $Recurse -Directory $Directory -Depth $Depth
    ForEach-Object $folder in $folders {
        Get-NTFSAccess -Path $folder.FullName -ExcludeInherited | ForEach-Object {
            if (($_.Account -like "LV\N-*") -or ($_.Account -like "LV\DT_*") -or ($_.Account -like "LV\B-*") -or ($_.Account -like "LV\P-*") -or ($_.Account -like "LV\AG_*")) {
                [pscustomobject]@{
                    Fullname = $folder.FullName
                    SecGroup = $_.Account
                }
            }
        }
    }
}

Function New-ADMigrationGroups {
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string]
    )
}

Function Set-MigrateNTFSRights {
    return 0
}

Function Initialize-RollbackMigration {
    #draai de migratie terug (functie moet nog uitgedacht worden)
    return 0
}

Function Write-MigrateLogging {
    #schrijf migratie logging weg, zodat er altijd kan worden nagegaan wat er gebeurt is
    Param(
        [Parameter]
        [ValidateSet('Error','Information','Warning','Critical')]
        [string]$LogLevel="Information",
        [Parameter(Mandatory=$true)]
        [string]$LogMessage        
    )
    $dateTime = Get-Date -Format "dd-MM-yyyy HH:mm:ss:fff"
    "$($dateTime): [$($logLevel)] - $($logMessage)" | Out-File -FilePath ($($logDir) + "MigrateLogging.txt") -Append
}