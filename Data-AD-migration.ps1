# Data AD Migration Tool

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch [System.IO.FileNotFoundException] {
    Write-MigrateLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory niet gelukt! Voer de volgende code uit om dit probleem op te lossen: Initialize-Module(ActiveDirectory)"
} catch {
    Write-MigrateLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory niet gelukt! $($error[-1])"
}

Import-Module NTFSSecurity -ErrorAction Stop

#Set Initial Variables
$workingDir = "D:\Migratie"         #Basis directory. LET OP: Geen \ op het einde toevoegen!
$ADSearchBase = "" #Use searchbase (example: OU=SecurityGroups,DC=contose,DC=com)

#VANAF HIER GEEN AANPASSINGEN MAKEN AAN HET SCRIPT#

$csvDir = "$($workingDir)\Csv\"      #locatie voor de export CSV's
$logDir = "$($workingDir)\Logging\"  #locatie voor de logging
$xmlDir = "$($workingDir)\Xml\"      #locatie voor XML bestanden

Function Initialize-Module ($m) {
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m -Verbose
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}
Function Set-MigrationBasics {
    If (!(Test-Path $workingDir)) {
        New-Item -ItemType Directory -Path $workingDir
        Write-MigrateLogging -LogMessage "Folder $($workingDir) aangemaakt."
    }

    If (!(Test-Path $csvDir)) {
        New-Item -ItemType Directory -Path $csvDir
        Write-MigrateLogging -LogMessage "Folder $($csvDir) aangemaakt."
    }

    If (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir
        Write-MigrateLogging -LogMessage "Folder $($logDir) aangemaakt."
    }

    If (!(Test-Path $xmlDir)) {
        New-Item -ItemType Directory -Path $xmlDir
        Write-MigrateLogging -LogMessage "Folder $($xmlDir) aangemaakt."
    }
}
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

Function Get-PathWithSecurityGroup {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$false,Mandatory=$true)]
        [string]$Path,
        [boolean]$Recurse=$true,
        [boolean]$Directory=$true,
        [int]$Depth=1
    )
    try {
        Write-MigrateLogging -LogMessage "Get-PathWithSecurityGroup() gestart"
        $folders = Get-ChildItem -Path $Path -Recurse $Recurse -Directory $Directory -Depth $Depth | Select-Object FullName
        ForEach-Object $folder in $folders {
            $NTFSGroups = Get-NTFSAccess -Path $folder.FullName -ExcludeInherited
            foreach ($NTFSGroup in $NTFSGroups) {
                if (($NTFSGroup.Account.AccountName -like "LV\N-*") -or ($NTFSGroup.Account.AccountName -like "LV\DT_*") -or ($NTFSGroup.Account.AccountName -like "LV\B-*") -or ($NTFSGroup.Account.AccountName -like "LV\P-*") -or ($NTFSGroup.Account.AccountName -like "LV\AG_*")) {
                    $NewSecGroup = New-MigrateReadGroup -SecurityGroup $NTFSGroup.Account.AccountName
                    $MigrationObjects = [pscustomobject]@{
                        Fullname = $folder.FullName
                        OldSecGroup = $NTFSGroup.Account.AccountName
                        NewSecGroup = $NewSecGroup
                    }
                }
            }
            $MigrationObjects | Export-Csv "$($csvDir)SecurityGroups.csv" -Delimiter ";" -Append -NoTypeInformation
            Write-MigrateLogging -LogMessage "Get-PathWithSecurityGroup() succesvol uitgevoerd." 
        }
    } catch {
        Write-Error "Foutje in Get-PathWithSecurityGroup()!" #Catch moet nog verder worden uitgewerkt
        Write-Migrate Logging -LogMessage "Get-PathWithSecurityGroup() fout opgetreden: $($error)" -LogLevel Error
    } finally {
        Write-Output "Functie volledig uitgevoerd. Controleer de output CSV ($($csvDir)Securitygroups.csv) en verwijder duplicate input.`nStart vervolgens CmdLet New-ADMigrationGroups."
    }
}

Function New-ADMigrationGroups {
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$false)]
        [string]$test
    )
    $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
    ForEach-Object $line in $csvFile {
        Write-Output "Creating AD Security group: $($line.NewSecGroup)"
    }
}

Function Set-MigrateNTFSRights {
    return 0
}

Function Initialize-RollbackMigration {
    #draai de migratie terug (functie moet nog uitgedacht worden)
    return 0
}
Function New-MigrateReadGroup {
    Param(
        [string]$SecurityGroup
    )

    if ($SecurityGroup -notmatch "DT_") {
        $SecurityGroupSplit = $SecurityGroup -split ("\\")
        $SecurityGroup = $SecurityGroupSplit[1]
        $SecurityGroup = $SecurityGroup.Substring(2)
        $SecurityGroup = "DT_Organisatie_" + $SecurityGroup + "_R"            
    } else {
        $SecurityGroup = (($SecurityGroup -split "\\")[1]) + "_R"
        if ($SecurityGroup -notmatch "DT_Organisatie") {
            $SecurityGroup = $SecurityGroup.Substring(3)
            $SecurityGroup = "DT_Organisatie_" + $SecurityGroup
        }
    }

    return $SecurityGroup.ToString()
}
Function Write-MigrateLogging {
    #schrijf migratie logging weg, zodat er altijd kan worden nagegaan wat er gebeurt is
    Param(
        [Parameter()]
        [ValidateSet('Error','Information','Warning','Critical')]
        [string]$LogLevel="Information",
        [Parameter(Mandatory=$true)]
        [string]$LogMessage        
    )
    $dateTime = Get-Date -Format "dd-MM-yyyy HH:mm:ss:fff"
    "$($dateTime): [$($LogLevel)] - $($LogMessage)" | Out-File -FilePath ($($logDir) + "MigrateLogging.txt") -Append
}