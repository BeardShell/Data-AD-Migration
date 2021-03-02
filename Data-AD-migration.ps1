<#
.SYNOPSIS
  Toolset for use with data / AD migration
.DESCRIPTION
  This script can be used to automate migration.
  It is capable of reading a disk or directory with a certain (or no) depth.
  From that starting point it is possible to create new AD Groups, Set NTFS rights, clear old Groups.
  Data copying itself is outside of the scope of this script
.INPUTS
  None
.OUTPUTS
  Securitygroups.csv
.NOTES
  Version:        0.2
  Author:         Stefan Lievers a.k.a. BeardShell
  Creation Date:  13-02-2021
  Purpose/Change: Test runs completed. Use only on backed-up environments.
  URL:            https://github.com/BeardShell/Data-AD-Migration

  Note: Some lines in this script have the sole purpose to serve the customer I wrote this for. Edit those lines accordingly.
  
.EXAMPLE
  Export-MigrationSecurityGroup -RootPath "E:\"
#>

#
# Todo-list
# ---------
# - Modularize more for broader use
# - Add more try/catch uses
# - Add proper error handling



# Test bit for module import
<#try {
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
}#>

#Set Initial Variables
$workingDir = "C:\Migratie"         #Base directory. IMPORTANT: Don't add a trailing backslash (\) at the end!
$ADSearchBase = ""                  #Use searchbase (example: OU=SecurityGroups,DC=contose,DC=com)

#--- DO NOT MAKE ANY ALTERATIONS TO THE SCRIPT BELOW THIS LINE ---#

$csvDir = "$($workingDir)\Csv\"     #location for csv files
$logDir = "$($workingDir)\Log\"     #location for log files

#region Helper functions
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
Function Convert-MigrationSecuritygroup {
    Param(
        [string]$SecurityGroup
    )
    $orgSecurityGroup = $SecurityGroup

    if ($SecurityGroup -match "l.wijz") {
        $SecurityGroup = $SecurityGroup + "_R"
        return $SecurityGroup.ToString()
    }
    if ($SecurityGroup -notmatch "DT_") {
        $SecurityGroupSplit = $SecurityGroup -split ("\\")
        $SecurityGroup = $SecurityGroupSplit[1]
        $SecurityGroup = $SecurityGroup.Substring(2)
        $SecurityGroup = "DT_Organisatie_" + $SecurityGroup
        if ($SecurityGroup.Length -gt 64) {
            $SecurityGroup = $SecurityGroup.Substring(0,60)
            $SecurityGroup = $SecurityGroup + "_R"
        }            
    } else {
        $SecurityGroup = (($SecurityGroup -split "\\")[1]) + "_R"
        if ($SecurityGroup -notmatch "DT_Organisatie") {
            $SecurityGroup = $SecurityGroup.Substring(3)
            $SecurityGroup = "DT_Organisatie_" + $SecurityGroup
        }
        if ($SecurityGroup.Length -gt 64) {
            $SecurityGroup = $SecurityGroup.Substring(0,60)
            $SecurityGroup = $SecurityGroup + "_R"
        }
    }
    Write-MigrationLogging -LogMessage "Converted $($orgSecurityGroup) to new name $($SecurityGroup.ToString())."
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
                    GroupName = $SecurityGroup.ToString()
                    Name = $_.SamAccountName
                }
            }
            Write-MigrationLogging -LogMessage "Saved $($SecurityGroup) to file $($csvDir)$($CSV)"
            $ADGroupMembers | Export-Csv -Path "$($csvDir)$($CSV)" -Delimiter ";" -NoTypeInformation
        } catch {
            Write-Error $error[-1]
        }
    }
}
#Original function created by Peter Mortensen (https://stackoverflow.com/users/63550/peter-mortensen). Many thanks to you sir!
#Edited by myself to my way of writing code and made it PowerShelly like with Param() block etc.
Function Initialize-Module {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $ModuleName}) {
        Write-Verbose "Module $($ModuleName) is already imported."
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
Function Reset-PowerShellGalleryStuff {
#Sometimes everything to use the PowerShell Gallery, NuGet and all that stuff is just plain old broken.
#To fix it there are several steps. Just run this function if necessary and try what you wanted to do again.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #TLS 1.0 and 1.1 are not supported, this is usually an issue these days (source: https://stackoverflow.com/questions/51406685/how-do-i-install-the-nuget-provider-for-powershell-on-a-unconnected-machine-so-i)
Register-PSRepository -Default  #Same as before, this appearantly is an issue sometimes. Encountered it often. (source: https://stackoverflow.com/questions/63385304/powershell-install-no-match-was-found-for-the-specified-search-criteria-and-mo)
Install-PackageProvider -Name NuGet #when things are working properly again, might as well install this packageprovider as well
}
#endregion Helper functions

Initialize-Module -ModuleName ActiveDirectory
Initialize-Module -ModuleName NTFSSecurity

Function Set-MigrationBasics {
    #Chech for directory existence and fix it if neccesary. 
    If (!(Test-Path $workingDir)) {
        New-Item -ItemType Directory -Path $workingDir
        Write-Output "Directory $($workingDir) created."
        #No Write-MigrationLogging in this step, it will fail for not having the $logDir yet.
    }

    If (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir
        Write-Output "Directory $($logDir) created."
        Write-MigrationLogging -LogMessage "Directory $($logDir) created."
    }

    If (!(Test-Path $csvDir)) {
        New-Item -ItemType Directory -Path $csvDir
        Write-Output "Directory $($csvDir) created."
        Write-MigrationLogging -LogMessage "Directory $($csvDir) created."
    }
}
Function Backup-MigrationStartingPoint { # Don't use this function anymore, it's done automatically if you use Export-MigrationSecurityGroups
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
        [Parameter(Mandatory=$true)]
        [string]$OUPath,
        [string]$Description="Created by New-ADMigration PowerShell function.",
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )
    PROCESS {
        try {
            if (Test-Path $CsvFile) {
                $csvFileImport = Import-Csv -Path "$($csvDir)SecurityGroups.csv" -Delimiter ";"
                foreach ($line in $csvFileImport) {
                    if ($PSCmdLet.ShouldProcess("AD Modify Security Groups", "Add-ADGroupMember")) {
                        $groupCheck = Get-ADGroup -LDAPFilter "(SAMAccountName=$($line.readonlyACL))"
                        if ($null -eq $groupCheck) {
                            New-ADGroup -DisplayName $line.readonlyACL -GroupScope DomainLocal -GroupCategory Security -Name $line.readonlyACL -SamAccountName $line.readonlyACL -Path $OUPath -Description $Description -ErrorAction SilentlyContinue
                            Write-Output "New AD Security Group ($($line.readonlyACL)) created in path: $($OUPath)"
                            Write-MigrationLogging -LogMessage "New AD Security Group ($($line.readonlyACL)) created in path: $($OUPath)"
                        } else {
                            Write-Output "AD Group $($line.readonlyACL) already exists. Skipped creating new group. This message can safely be ignored."
                            Write-MigrationLogging -LogMessage "AD Group $($line.readonlyACL) already exists. Skipped creating new group. This log message can safely be ignored."
                        }
                    }
                }
            } else {
                Write-Warning "File $($CsvFile) not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
            }
        } catch [System.IO.FileNotFoundException] {
            Write-Error "Module niet geladen?"
        } catch {
            Write-Error $error.message
        }
    }
}
Function Add-MigrationReadOnlyMembers {
    #Import users from modify groups to the newly created ReadOnly Groups
        [CmdLetBinding()]
    Param (
        [Parameter()]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        try {
            if (Test-Path $CsvFile) {
                $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

                foreach ($line in $CsvFileImported) {
                    $modifyACL = $line.modifyACL.Substring(3)
                    $currentMembers = Get-ADGroupMember -Identity $modifyACL
                    foreach ($aclMember in $currentMembers) {
                        Get-ADGroup -Identity $line.readonlyACL | Add-ADGroupMember -Members $aclMember.SamAccountName
                        Write-Output "New member ($($aclMember.SamAccountName)) added to Security Group $($line.readonlyACL)"
                        Write-MigrationLogging -LogMessage "New member ($($aclMember.SamAccountName)) added to Security Group $($line.readonlyACL)"
                    }
                }
            } else {
                Write-Warning "File $($CsvFile) not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
            }
        } catch {
            Write-Error $Error
        }
    }
}
Function Set-MigrationNTFSRights {
    [CmdLetBinding()]
    Param (
        [Parameter()]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )
    PROCESS {
        try {
            if (Test-Path $CsvFile) {
                $csvFileImport = Import-Csv -Path $CsvFile -Delimiter ";"
                foreach ($line in $csvFileImport) {
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
                Write-Warning "File $($CsvFile) not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
            }
        } catch {
            Write-Error "Fuck!"
        }
    }
}
Function Clear-MigrationModifyGroups {
    [CmdLetBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter()]
        [string]$CsvFile="$($csvDir)Securitygroups.csv"
    )

    PROCESS {
        if ($PSCmdLet.ShouldProcess("AD Clear/Empty Security Group", "Remove-ADGroupMember")) {
            if (Test-Path $CsvFile) {
                $CsvFileImported = Import-Csv -Path $CsvFile -Delimiter ";"

                foreach ($line in $CsvFileImported) {
                    $modifyACL = $line.modifyACL.Substring(3)
                    Get-ADGroupMember $modifyACL | ForEach-Object { Remove-ADGroupMember -Identity $modifyACL -Members $_.SamAccountName -Confirm:$false }
                    Write-Output "All members removed from security group $($modifyACL)"
                    Write-MigrationLogging -LogMessage "All members removed from security group $($modifyACL)"
                }
            } else {
                Write-Warning "File $($CsvFile) not found!"
                Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
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
        [string[]]$ModifyGroup=$null,
        [Parameter(Mandatory=$false)]
        [string[]]$RootPath=$null,
        [Parameter(Mandatory=$false)]
        [string[]]$ReadGroup=$null,
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
                                $csvFilename = $csvDir + $compareObject + ".csv"
                                $groupCheck = Get-ADGroup -LDAPFilter "(SAMAccountName=$($line.readonlyACL))"
                                if ($null -eq $groupCheck) {
                                    if (Test-Path $csvFilename) {
                                        $readonlyCSV = Import-Csv -Path $csvFilename -Delimiter ";"
                                        foreach ($member in $readonlyCSV) {
                                            Add-ADGroupMember -Identity $compareObject -Members $member.Name
                                            Write-Output "Adding $($member.Name) to $($compareObject) (source: $($csvFilename))"
                                            Write-MigrationLogging -LogMessage "Adding $($member.Name) to $($compareObject) (source: $($csvFilename))"
                                        }
                                    }
                                } else {
                                    $readMembers = Get-ADGroupMember -Identity $line.readonlyACL
                                    foreach ($member in $readMembers) {
                                        Add-ADGroupMember -Identity $compareObject -Members $member.SamAccountName
                                        Write-Output "Adding $($member.SamAccountName) to $($compareObject) (source: $($line.readonlyACL))"
                                        Write-MigrationLogging -LogMessage "Adding $($member.SamAccountName) to $($compareObject) (source: $($line.readonlyACL))"
                                    }
                                }
                            } 
                        }
                    }
                }
                if ($null -ne $RootPath) {
                    Write-Output $RootPath
                    Write-Output "Run Path commands"
                }
                if ($null -ne $ReadGroup) {
                    foreach ($groupItem in $ReadGroup) {
                        foreach ($line in $CsvFileImported) {
                            $compareObject = $line.readonlyACL                            
                            if ((Compare-Object -ReferenceObject $groupItem -DifferenceObject $compareObject -IncludeEqual | Where-Object {$_.SideIndicator -eq "=="})) {
                                $modifyObject = $line.modifyACL
                                if ($modifyObject -match "LV\\") {                      # double slash \\ used, one for the character slash and one for escaping the slash
                                    $modifyObject = $modifyObject.Substring(3)
                                }
                                $csvFilename = $csvDir + $modifyObject + ".csv"
                                $groupCheck = Get-ADGroup -LDAPFilter "(SAMAccountName=$($line.readonlyACL))"
                                if ($null -eq $groupCheck) {
                                    if (Test-Path $csvFilename) {
                                        $modifyCSV = Import-Csv -Path $csvFilename -Delimiter ";"
                                        foreach ($member in $modifyCSV) {
                                            Add-ADGroupMember -Identity $modifyObject -Members $member.Name
                                            Write-Output "Adding $($member.Name) to $($modifyObject) (source: $($csvFilename))"
                                            Write-MigrationLogging -LogMessage "Adding $($member.Name) to $($modifyObject) (source: $($csvFilename))"
                                        }
                                    }
                                } else {
                                    $readMembers = Get-ADGroupMember -Identity $line.readonlyACL
                                    foreach ($member in $readMembers) {
                                        Add-ADGroupMember -Identity $modifyObject -Members $member.SamAccountName
                                        Write-Output "Adding $($member.SamAccountName) to $($modifyObject) (source: $($line.readonlyACL))"
                                        Write-MigrationLogging -LogMessage "Adding $($member.SamAccountName) to $($modifyObject) (source: $($line.readonlyACL))"
                                    }
                                }
                            }
                        } 
                    }
                }
                if (($continueFlag -eq $true) -or ($null -eq $continueFlag) -and ($null -eq $ModifyGroup) -and ($null -eq $ReadGroup)) {
                    foreach ($line in $CsvFileImported) {
                        Get-ADGroupMember -Identity $line.readonlyACL | ForEach-Object {Add-ADGroupMember -Identity ($line.modifyACL).Substring(3) -Members $_.SamAccountName}
                        Write-Output "Rollback: Adding members to security group $($line.modifyACL). (Source: $($line.readonlyACL))"
                        Write-MigrationLogging -LogMessage "Rollback: Adding members to security group $($line.modifyACL). (Source: $($line.readonlyACL))"
                    }
                }
            } 
        } else {
            Write-Warning "File $($CsvFile) not found!"
            Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
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
            Write-Warning "File $($CsvFile) not found!"
            Write-MigrationLogging -LogLevel Warning -LogMessage "File $($CsvFile) not found!"
        }
    }
}
#endregion Servicedesk function