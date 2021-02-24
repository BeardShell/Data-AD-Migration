# Data AD Migration Tool
# Written by Stefan a.k.a. BeardShell
# Feel free to use any of these functions for your own use as you see fit (see license)
# Always keep the original author (me) mentioned if you use any of this
# Credits given where credit is due
#
# Version 0.1
# Not tested in production yet
# Creation date: 13-02-2021
# For the latest modifications on this script see: https://github.com/BeardShell/Data-AD-Migration
#
# Some lines in this script have the sole purpose to serve the customer I wrote this for. Edit those lines accordingly.
#
# Todo-list
# ---------
# - Add more Write-MigrationLogging content in the various functions
# - Add decent synopsis (help information)
# - Modularize more for broader use
# - Add more try/catch uses
# - Add proper Begin, Process, End codeblocks
# - Add ShouldProcess() support like it is supposed to in all applicable functions

# Test bit for module import
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch [System.IO.FileNotFoundException] {
    Write-MigrationLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory failed! Try this code to fix the problem: Initialize-Module(ActiveDirectory)"
} catch {
    Write-MigrationLogging -LogLevel "Critical" -LogMessage "Import-Module ActiveDirectory failed! $($error[-1])"
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
        #No Write-MigrationLogging in this step, it will fail for not having the $logDir yet.
    }

    If (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir
        Write-MigrationLogging -LogMessage "Directory $($logDir) created."
    }

    If (!(Test-Path $csvDir)) {
        New-Item -ItemType Directory -Path $csvDir
        Write-MigrationLogging -LogMessage "Directory $($csvDir) created."
    }

    If (!(Test-Path $xmlDir)) {
        New-Item -ItemType Directory -Path $xmlDir
        Write-MigrationLogging -LogMessage "Directory $($xmlDir) created."
    }
}
Function Backup-MigrationStartingPoint {
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string]$ADSearchBase
    )
    PROCESS {
        try {
            Write-MigrationLogging -LogMessage "Backup-MigrationStartingPoint() started with SearchBase $($ADSearchBase)"
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
                Write-MigrationLogging -LogMessage "AD group members from $($ADGroup.Name): saved in $($csvDir)$($CSV)"
            }
        } Catch {
            Write-Error $error.Message
        } Finally {
            Write-Output "Backup-MigrationStartingPoint() executed succesfully. See logging for full details"
            Write-MigrationLogging -LogMessage "Backup-MigrationStartingPoint() executed succesfully"
        }
    }
}
Function Export-MigrationSecurityGroups {
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
                            newACL = (Convert-MigrationSecuritygroup -SecurityGroup $id.IdentityReference)
                        }
                        $summaryArray += $summary
                        $summary | Export-Csv -Path "$($csvDir)Securitygroups.csv" -Delimiter ";" -Append -NoTypeInformation
                    }
                }
            }
        } catch {
            Write-Error "Oops, my bad! " $PSItem
            Write-Migrate Logging -LogMessage "Export-MigrationSecurityGroups() error occured: $($error)" -LogLevel Error
        }
    }
}
Function New-MigrationADGroups {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$false)]
        [string]$OUPath,
        [string]$Description="Created by New-ADMigration PowerShell function."
    )
    try {
        $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
        foreach ($line in $csvFile) {
            if ($PSCmdLet.ShouldProcess("AD Modify Security Groups", "Add-ADGroupMember")) {
                New-ADGroup -DisplayName $line.newACL -GroupScope DomainLocal -GroupCategory Security -Name $line.newACL -SamAccountName $line.newACL -Path $OUPath -Description $Description -WhatIf
                Write-MigrationLogging -LogMessage "New AD Security Group created: $($OUPath)"
            }
        }
    } catch [System.IO.FileNotFoundException] {
        Write-Error "Module niet geladen?"
    }
}
Function Add-MigrationReadOnlyMembers {
    #Import users from modify groups to the newly created ReadOnly Groups
        [CmdLetBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

        foreach ($line in $CsvFileImported) {
            $currentACL = $line.currentACL.Substring(3)
            $currentMembers = Get-ADGroupMember -Identity $currentACL
            foreach ($aclMember in $currentMembers) {
                Get-ADGroup -Identity $line.newACL | Add-ADGroupMember -Members $aclMember.SamAccountName -WhatIf
            }
        }
    }
}
Function Set-MigrationNTFSRights {
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
Function Initialize-MigrationRollback {
    [CmdLetBinding(ConfirmImpact="Low",
        SupportsShouldProcess=$true)]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]
        $All,
        [Parameter(Mandatory=$false)]
        [string[]]$ModifyGroup,
        [Parameter(Mandatory=$false)]
        [string[]]$Path,
        [Parameter(Mandatory=$false)]
        [string[]]$ReadGroup,
        [Parameter(Mandatory=$false)]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    $confirmationMessage = "I AM VERY SURE"
    $continueFlag = $null

    if ($PSCmdLet.ShouldProcess("AD Modify Security Groups", "Add-ADGroupMember")) {
        if ($All -eq $true) {
            Write-Warning "All modify groups will be filled with members again. Please make sure this is your intended action."
            $checkInput = Read-Host "Please type in $($confirmationMessage) to confirm you want to continue"
            if ($checkInput -eq $confirmationMessage) {
                $continueFlag = $true
            } else {
                Write-Error "Wrong confirmation message entered. Script stopped for safety reasons.`nIf you do want to perform a rollback run this script/function again."
            }
            #-All is chosen, no need to read anything else, so we don't want to run anything else
            $ModifyGroup = $null
            $Path = $null
            $ReadGroup = $null
        }
        if ($null -ne $ModifyGroup) {
            Write-Output "Run ModifyGroup commands"
        }
        if ($null -ne $Path) {
            Write-Output "Run Path commands"
        }
        if ($null -ne $ReadGroup) {
            Write-Output "Run Readgroup commands"
        }
        if (($continueFlag -eq $true) -or ($null -eq $continueFlag)) {
            $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

            foreach ($line in $CsvFileImported) {
                #Get-ADGroupMember -Identity $line.newACL | ForEach-Object {Add-ADGroupMember -Identity ($line.currentACL).Substring(3) -Members $_.SamAccountName -WhatIf}
            }
        }
    } 
}
Function Convert-MigrationSecuritygroup {
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
Function Write-MigrationLogging {
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