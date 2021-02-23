# Data AD Migration Tool

# Test bit for module import
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch [System.IO.FileNotFoundException] {
    Write-MigrateLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory failed! Try this code to fix the problem: Initialize-Module(ActiveDirectory)"
} catch {
    Write-MigrateLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory failed! $($error[-1])"
}

Import-Module NTFSSecurity -ErrorAction Stop

#Set Initial Variables
$workingDir = "D:\Migratie"         #Base directory. IMPORTANT: Don't add a trailing backslash (\) at the end!
$ADSearchBase = ""                  #Use searchbase (example: OU=SecurityGroups,DC=contose,DC=com)

#--- DO NOT MAKE ANY ALTERATIONS TO THE SCRIPT BELOW THIS LINE ---#

$csvDir = "$($workingDir)\Csv\"     #location for csv files
$logDir = "$($workingDir)\Log\"     #location for log files
$xmlDir = "$($workingDir)\Xml\"     #location for xml files, don't know if we will use this

#NOT my module, have to check it and make it consistence to the way I write. Also I have to check where I found it to give credits to the original author!
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
    #Chech for directory existence and fix it if neccesary. 
    If (!(Test-Path $workingDir)) {
        New-Item -ItemType Directory -Path $workingDir
        #No Write-MigrateLogging in this step, it will fail for not having the $logDir yet.
    }

    If (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir
        Write-MigrateLogging -LogMessage "Directory $($logDir) created."
    }

    If (!(Test-Path $csvDir)) {
        New-Item -ItemType Directory -Path $csvDir
        Write-MigrateLogging -LogMessage "Directory $($csvDir) created."
    }

    If (!(Test-Path $xmlDir)) {
        New-Item -ItemType Directory -Path $xmlDir
        Write-MigrateLogging -LogMessage "Directory $($xmlDir) created."
    }
}

#New Function names to unify it
#Backup-MigrationStartingPoint (Initialize-Migration)
#Export-MigrationSecurityGroups (Get-PathWithSecurityGroups)
#Set-MigrationNTFSRights (Set-MigrateNTFSRights)
#New-MigrationADGroups (New-ADMigrationGroups)
#Initialize-MigrationRollback (Initialize-RollbackMigration)
#Write-MigrationLogging (Write-MigrateLogging)
#Convert-MigrationSecuritygroup (New-MigrateReadGroup)
Function Initialize-Migration {
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string]$ADSearchBase
    )
    PROCESS {
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
                Write-Verbose "AD group members from $($ADGroup.Name): saved in $($csvDir)$($CSV)"
                Write-MigrateLogging -LogMessage "AD group members from $($ADGroup.Name): saved in $($csvDir)$($CSV)"
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
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true, Position=0)]
        [string]$RootPath
        #[int]$Depth=1
    )
    PROCESS {
        try {
            $DfsPath = Get-ChildItem $RootPath
    
            $directory = @()
            $summaryArray = @()
    
            foreach ($path in $DfsPath) {
                $directory += $path.FullName   
            }
            foreach ($subject in $directory) { 
                foreach ($id in ((Get-Acl -Path $subject).Access | Where-Object {$_.IsInherited -eq $false})) {
                    if (($id.IdentityReference -like "LV\DT_*") -or ($id.IdentityReference -like "LV\B-*") -or ($id.IdentityReference -like "LV\N-*" -or ($id.IdentityReference -like "LV\P-*") -or ($id.IdentityReference -like "LV\AG-*"))) {
                        $summary = [pscustomobject] @{
                            DFSPath = $subject
                            currentACL = $id.IdentityReference
                            newACL = (New-MigrateReadGroup -SecurityGroup $id.IdentityReference)
                        }
                        $summaryArray += $summary
                        $summary | Export-Csv -Path "$($csvDir)Securitygroups.csv" -Delimiter ";" -Append -NoTypeInformation
                    }
                }
            }
        } catch {
            Write-Error "Oops, my bad! " $PSItem
            Write-Migrate Logging -LogMessage "Get-PathWithSecurityGroup() error occured: $($error)" -LogLevel Error
        }
    }
}

Function New-ADMigrationGroups {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$false)]
        [string]$OUPath,
        [string]$Description="Created by New-ADMigration PowerShell function."
    )
    $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
    foreach ($line in $csvFile) {
        New-ADGroup -DisplayName $line.newACL -GroupScope DomainLocal -GroupCategory Security -Name $line.newACL -SamAccountName $line.newACL -Path $OUPath -Description $Description -WhatIf
        if ($WhatIfPreference -eq $false) {
            Write-MigrateLogging -LogMessage "New AD Security Group created: $($OUPath)"
        }
    }
}

Function Set-MigrateNTFSRights {
    $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
    foreach ($line in $csvFile) {
        Add-NTFSAccess -Path $line.DFSPath -Account $line.newACL -AccessRights ReadAndExecute -AccessType Allow -AppliesTo ThisFolderSubfoldersAndFiles
    }
}

Function Clear-MigrationModifyGroups {
    [CmdLetBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )
    PROCESS {
        $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

        foreach ($line in $CsvFileImported) {
            $currentACL = $line.currentACL.Substring(3)
            Get-ADGroupMember $currentACL | ForEach-Object { Remove-ADGroupMember -Identity $currentACL -Members $_.SamAccountName -Confirm:$false -WhatIf }
        }
    }
}

Function Add-MigrationReadOnlyMembers {
    #Import users from modify groups to the newly created ReadOnly Groups
}

Function Get-MigrationPreviousRights {
    [CmdLetBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$DfsPath,
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        $file = Import-Csv $CsvFile -Delimiter ";"
        foreach ($line in $file) {
            if ((Compare-Object -ReferenceObject $DfsPath -DifferenceObject $line.DFSPath -IncludeEqual | Where-Object {$_.SideIndicator -eq "=="})) {
                $previousSecGroup = Import-Csv ($csvDir + (($line.currentACL).Substring(3)) + ".csv") -Delimiter ";"
                Write-Output "Users/Groups with previous access to $($DfsPath):"
                Write-Output "----------"
                foreach ($user in $previousSecGroup) {
                    Write-Output $user.Name
                }
                Write-Output "To restore access rights add chosen user to $($line.currentACL)"
            }
        }
    }
}

Function Initialize-RollbackMigration {
    #revert migration, yet to be build
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
    #Function to write logging to keep a log of all that's happened.
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