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
$ADSearchBase = "" #Use searchbase (example: OU=SecurityGroups,DC=contose,DC=com)

#--- DO NOT MAKE ANY ALTERATIONS TO THE SCRIPT BELOW THIS LINE ---#

$csvDir = "$($workingDir)\Csv\"      #locatie voor de export CSV's
$logDir = "$($workingDir)\Log\"      #locatie voor de logging
$xmlDir = "$($workingDir)\Xml\"      #locatie voor XML bestanden

#NOT my module, have to check it and make it consistence to the way I wright. Also I have to check where I found it to give credits to the original author!
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
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true, Position=0)]
        [string]$RootPath
        #[int]$Depth=1
    )
    PROCESS {
        try {
            Write-Output $RootPath
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
        } finally {
            #Write-Output "Status: Success. Check the output CSV ($($csvDir)Securitygroups.csv) if you're satisfied.`nIf required, run CmdLet New-ADMigrationGroups."
        }
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