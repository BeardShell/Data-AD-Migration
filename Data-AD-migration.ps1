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

try {
    Import-Module NTFSSecurity -ErrorAction Stop
} catch [System.IO.FileNotFoundException] {
    Write-MigrationLogging -LogLevel "Critical" -LogMessage "Import-Module NTFSSecurity failed! Try this code to fix the problem: Initialize-Module(ActiveDirectory)"
} catch {
    Write-MigrationLogging -LogLevel "Critical" -LogMessage "Import-Module NTFSSecurity failed! $($error[-1])"
}

#Set Initial Variables
$workingDir = "D:\Migratie"         #Base directory. IMPORTANT: Don't add a trailing backslash (\) at the end!
$ADSearchBase = ""                  #Use searchbase (example: OU=SecurityGroups,DC=contose,DC=com)

#--- DO NOT MAKE ANY ALTERATIONS TO THE SCRIPT BELOW THIS LINE ---#

$csvDir = "$($workingDir)\Csv\"     #location for csv files
$logDir = "$($workingDir)\Log\"     #location for log files
#$xmlDir = "$($workingDir)\Xml\"     #location for xml files, don't know if we will use this

#region Helper functions
Function Convert-MigrationSecuritygroup {
    Param(
        [string]$SecurityGroup
    )
    if ($SecurityGroup -match "l.wijz") {
        return $SecurityGroup.ToString()
    }
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
Function Backup-MigrationSecurityGroup {
    Param (
        [string]$SecurityGroup
    )

    PROCESS {
        try {
            $CSV = ($SecurityGroup) + ".csv"
            $ADGroupMembers = Get-ADGroupMember -Identity $SecurityGroup | ForEach-Object {
                [pscustomobject]@{
                    GroupName = $ADGroup.Name
                    Name = $_.SamAccountName
                }
            }
            $ADGroupMembers | Export-Csv -Path "$($csvDir)$($CSV)" -Delimiter ";"
        } catch {
            Write-Error $error[-1]
        }
    }
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
#endregion Helper functions

#Original function created by Peter Mortensen (https://stackoverflow.com/users/63550/peter-mortensen)
Function Initialize-Module {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $ModuleName}) {
        Write-Output "Module $($ModuleName) is already imported."
    } else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $ModuleName}) {
            Import-Module $ModuleName -Verbose
        } else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $ModuleName | Where-Object {$_.Name -eq $ModuleName}) {
                Install-Module -Name $ModuleName -Force -Verbose -Scope CurrentUser
                Import-Module $ModuleName -Verbose
            } else {
                # If module is not imported, not available and not in online gallery then abort
                Write-Output "Module $ModuleName not imported, not available and not in online gallery, exiting."
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
        [string]$RootPath,
        [int]$Depth=0
    )
    PROCESS {
        try {
            if ($Depth -eq 0) {
                $DfsPath = Get-ChildItem $RootPath -Directory
                Write-Verbose "Running without -Depth"
            } else {
                $DfsPath = Get-ChildItem $RootPath -Directory-Depth $Depth
                Write-Verbose "Running with -Depth"
            }

            if (Test-Path("$($csvDir)Securitygroups.csv")) {
                Write-Warning "Path $($csvDir)Securitygroups.csv already exists!`n`nThe entire script depends on this file. Please back-up the current file (rename it or copy it) and remove the Securitygroups.csv"
                Write-Error "Overwriting the Securitygroups.csv file is not allowed.`nPlease remember that a rollback scenario is not possible when this file is incorrect or missing."
                Break;
            }
    
            $directory = @()
            $summaryArray = @()
    
            foreach ($path in $DfsPath) {
                $directory += $path.FullName   
            }

            foreach ($subject in $directory) { 
                Write-Verbose "Processing $($subject)"
                foreach ($id in ((Get-Acl -Path $subject).Access | Where-Object {$_.IsInherited -eq $false})) {
                    if (($id.IdentityReference -like "LV\DT_*") -or ($id.IdentityReference -like "LV\B-*") -or ($id.IdentityReference -like "LV\N-*" -or ($id.IdentityReference -like "LV\P-*") -or ($id.IdentityReference -like "LV\AG-*") -or ($id.IdentityReference -like "LV\l.wijz*"))) {
                        $SecurityGroup = ($id.IdentityReference).ToString()
                        $securityGroup = $SecurityGroup.Substring(3)
                        Backup-MigrationSecurityGroup -SecurityGroup $SecurityGroup
                        $summary = [pscustomobject] @{
                            DFSPath = $subject
                            modifyACL = $id.IdentityReference
                            readonlyACL = (Convert-MigrationSecuritygroup -SecurityGroup $id.IdentityReference)
                        }
                        $summaryArray += $summary
                        $summary | Export-Csv -Path "$($csvDir)Securitygroups.csv" -Delimiter ";" -Append -NoTypeInformation
                    }
                }
            }
            if (Test-Path("$($csvDir)Securitygroups.csv")) {
                Write-Output "The file $($csvDir)Securitygroups.csv is succesfully created. Back-up this file NOW!"
                Write-Output "The SecurityGroups.csv file is the key component to perform other functions and most importantly to launch a rollback scenario."
                Write-Output "Upon losing this file all information is lost and has to be restored manually based on the logging created."
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
        [string]$Description="Created by New-ADMigration PowerShell function.",
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )
    if ($PSCmdLet.ShouldProcess("AD Create new security group", "New-ADGroup")) {
        try {
            if (Test-Path $CsvFile) {
                $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
                foreach ($line in $csvFile) {
                    if ($PSCmdLet.ShouldProcess("AD Modify Security Groups", "Add-ADGroupMember")) {
                        New-ADGroup -DisplayName $line.readonlyACL -GroupScope DomainLocal -GroupCategory Security -Name $line.readonlyACL -SamAccountName $line.readonlyACL -Path $OUPath -Description $Description -WhatIf
                        Write-MigrationLogging -LogMessage "New AD Security Group created: $($OUPath)"
                    }
                }
            } else {
                Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
            }
        } catch [System.IO.FileNotFoundException] {
            Write-Error "Module niet geladen?"
        }
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
        if (Test-Path $CsvFile) {
            $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

            foreach ($line in $CsvFileImported) {
                $modifyACL = $line.modifyACL.Substring(3)
                $currentMembers = Get-ADGroupMember -Identity $modifyACL
                foreach ($aclMember in $currentMembers) {
                    Get-ADGroup -Identity $line.readonlyACL | Add-ADGroupMember -Members $aclMember.SamAccountName -WhatIf
                }
            }
        } else {
            Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
            Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
        }
    }
}
Function Set-MigrationNTFSRights {
    [CmdLetBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )
    PROCESS {
        try {
            if (Test-Path $CsvFile) {
                $csvFile = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
                Write-Output $?
                foreach ($line in $csvFile) {
                    Add-NTFSAccess -Path $line.DFSPath -Account $line.readonlyACL -AccessRights ReadAndExecute -AccessType Allow -AppliesTo ThisFolderSubfoldersAndFiles -ErrorAction SilentlyContinue
                    if ($? -eq $true) {
                        Write-MigrationLogging -LogMessage "NTFS Rights (ReadAndExecute) set to $($line.readonlyACL)"
                        Write-Output "NTFS Rights (ReadAndExecute) set to $($line.readonlyACL)"
                    } else {
                        Write-MigrationLogging -LogLevel Error -LogMessage "Error when settings NTFS rights to $($line.readonlyACL) (Error: $($error[-1])"
                        Write-Warning "Error when settings NTFS rights to $($line.readonlyACL) (Error: $($error[-1])"
                    }
                }
            } else {
                Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
            }
        } catch {
            Write-Error $error[-1]
        }
    }
}
Function Clear-MigrationModifyGroups {
    [CmdLetBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        if ($PSCmdLet.ShouldProcess("AD Clear/Empty Security Group", "Remove-ADGroupMember")) {
            if (Test-Path $CsvFile) {
                $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

                foreach ($line in $CsvFileImported) {
                    $modifyACL = $line.modifyACL.Substring(3)
                    Get-ADGroupMember $modifyACL | ForEach-Object { Remove-ADGroupMember -Identity $modifyACL -Members $_.SamAccountName -Confirm:$false -WhatIf }
                }
            } else {
                Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
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

    PROCESS {
        if (Test-Path $CsvFile) {
            $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"
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
                    foreach ($groupItem in $ModifyGroup) {
                        foreach ($line in $CsvFileImported) {
                            if ($groupItem -notmatch "LV\\") {                      # double slash \\ used, one for the character slash and one for escaping the slash
                                $compareObject = ($line.modifyACL).Substring(3)
                            } else {
                                $compareObject = $line.modifyACL
                            }
                            
                            if ((Compare-Object -ReferenceObject $groupItem -DifferenceObject $compareObject -IncludeEqual | Where-Object {$_.SideIndicator -eq "=="})) {
                                Write-Output $line
                            }
                        }
                    }
                }
                if ($null -ne $Path) {
                    Write-Output "Run Path commands"
                }
                if ($null -ne $ReadGroup) {
                    Write-Output "Run Readgroup commands"
                }
                if (($continueFlag -eq $true) -or ($null -eq $continueFlag)) {
                    foreach ($line in $CsvFileImported) {
                        #Get-ADGroupMember -Identity $line.readonlyACL | ForEach-Object {Add-ADGroupMember -Identity ($line.modifyACL).Substring(3) -Members $_.SamAccountName -WhatIf}
                    }
                }
            } 
        } else {
            Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
            Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
        }
    }
}
#region Servicedesk function
Function Get-MigrationPreviousRights {
    [CmdLetBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$DfsPath,
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        if (Test-Path $CsvFile) {
            $file = Import-Csv $CsvFile -Delimiter ";"
            foreach ($line in $file) {
                if ((Compare-Object -ReferenceObject $DfsPath -DifferenceObject $line.DFSPath -IncludeEqual | Where-Object {$_.SideIndicator -eq "=="})) {
                    $previousSecGroup = Import-Csv ($csvDir + (($line.modifyACL).Substring(3)) + ".csv") -Delimiter ";"
                    Write-Output "Users/Groups with previous access to $($DfsPath):"
                    Write-Output "----------"
                    foreach ($user in $previousSecGroup) {
                        Write-Output $user.Name
                    }
                    Write-Output "To restore access rights add chosen user to $($line.modifyACL)"
                }
            }
        } else {
            Write-Warning "File $($csvDir)SecurityGroups.csv not found!"
            Write-MigrationLogging -LogLevel Warning -LogMessage "File $($csvDir)SecurityGroups.csv not found!"
        }
    }
}
#endregion Servicedesk function