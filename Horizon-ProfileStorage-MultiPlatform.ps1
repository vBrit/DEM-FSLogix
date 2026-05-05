<#
.SYNOPSIS
Configures and validates Omnissa DEM and FSLogix profile storage.

.DESCRIPTION
Supports:
  - WindowsFileServer: creates folders, creates SMB shares, applies NTFS ACLs, validates.
  - NutanixFiles: applies NTFS ACLs to existing SMB shares and validates NTFS only.

.EXAMPLE
.\Horizon-ProfileStorage-MultiPlatform.ps1 -StorageType WindowsFileServer -Workload Both

.EXAMPLE
.\Horizon-ProfileStorage-MultiPlatform.ps1 -StorageType NutanixFiles -Workload FSLogix

.EXAMPLE
.\Horizon-ProfileStorage-MultiPlatform.ps1 -StorageType NutanixFiles -Workload DEM -Mode ValidateOnly

.REFERENCES
Omnissa DEM Configuration Share:
https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/DynamicEnvironmentManagerConfigurationShare.html

Omnissa DEM Profile Archives Share:
https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/ProfileArchivesShare.html

Microsoft FSLogix SMB Storage Permissions:
https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('WindowsFileServer','NutanixFiles')]
    [string]$StorageType,

    [Parameter(Mandatory)]
    [ValidateSet('DEM','FSLogix','Both')]
    [string]$Workload,

    [ValidateSet('ConfigureAndValidate','ValidateOnly')]
    [string]$Mode = 'ConfigureAndValidate'
)

$ErrorActionPreference = 'Stop'

# -----------------------------
# CUSTOMISE THESE VALUES
# -----------------------------

# Windows File Server root
$DriveLetter = 'D:'
$RootFolder  = 'ProfileStorage'

# FSLogix
$FSLogixFolder = 'FSLogix'
$FSLogixShare  = 'FSLogix'
$FSLogixUNC    = '\\NUTANIX-FILES-FQDN\FSLogix'

$FSLogixAdmins = 'DOMAIN\FSLogix-Admins'
$FSLogixUsers  = 'DOMAIN\FSLogix-Users'

# DEM
$DEMConfigFolder   = 'DEM-Config'
$DEMProfilesFolder = 'DEM-Profiles'

$DEMConfigShare   = 'DEM-Config'
$DEMProfilesShare = 'DEM-Profiles'

$DEMConfigUNC   = '\\NUTANIX-FILES-FQDN\DEM-Config'
$DEMProfilesUNC = '\\NUTANIX-FILES-FQDN\DEM-Profiles'

$DEMAdmins    = 'DOMAIN\DEM-Admins'
$DEMUsers     = 'DOMAIN\DEM-Users'
$DEMComputers = 'DOMAIN\DEM-Computers'

$EnableDEMComputerEnvironmentSettingsSupport = $true

# -----------------------------
# COMMON FUNCTIONS
# -----------------------------

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created folder: $Path"
    }
    else {
        Write-Host "Folder already exists: $Path"
    }
}

function Ensure-SmbShare {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$FullAccess,
        [string[]]$ChangeAccess,
        [string[]]$ReadAccess
    )

    $share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue

    if ($share) {
        if ($share.Path -ne $Path) {
            throw "Share '$Name' exists but points to '$($share.Path)', not '$Path'."
        }

        Set-SmbShare -Name $Name `
            -CachingMode None `
            -FolderEnumerationMode AccessBased `
            -Force | Out-Null
    }
    else {
        $params = @{
            Name                  = $Name
            Path                  = $Path
            CachingMode           = 'None'
            FolderEnumerationMode = 'AccessBased'
        }

        if ($FullAccess)   { $params.FullAccess   = $FullAccess }
        if ($ChangeAccess) { $params.ChangeAccess = $ChangeAccess }
        if ($ReadAccess)   { $params.ReadAccess   = $ReadAccess }

        New-SmbShare @params | Out-Null
        Write-Host "Created SMB share: $Name"
    }
}

function Reset-NtfsInheritance {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Path is not accessible: $Path"
    }

    icacls $Path /inheritance:r | Out-Null
}

function Show-ValidationResult {
    param([object[]]$Results)

    $Results | Format-Table -AutoSize

    if ($Results.Result -contains 'FAIL') {
        Write-Warning "One or more validation checks failed."
    }
}

# -----------------------------
# FSLOGIX FUNCTIONS
# -----------------------------

function Set-FSLogixAcl {
    param([Parameter(Mandatory)][string]$Path)

    Reset-NtfsInheritance -Path $Path

    icacls $Path /remove:g "$FSLogixUsers" 2>$null | Out-Null
    icacls $Path /remove:g "$FSLogixAdmins" 2>$null | Out-Null
    icacls $Path /remove:g "CREATOR OWNER" 2>$null | Out-Null
    icacls $Path /remove:g "SYSTEM" 2>$null | Out-Null

    icacls $Path /grant:r "CREATOR OWNER:(OI)(CI)(IO)(M)" | Out-Null
    icacls $Path /grant:r "SYSTEM:(OI)(CI)(F)" | Out-Null
    icacls $Path /grant:r "$FSLogixAdmins:(OI)(CI)(F)" | Out-Null
    icacls $Path /grant:r "$FSLogixUsers:(M)" | Out-Null
}

function Test-FSLogixAcl {
    param([Parameter(Mandatory)][string]$Path)

    $aclText = icacls $Path
    $aclObj  = Get-Acl $Path

    $adminPattern = [regex]::Escape($FSLogixAdmins) + ':\(OI\)\(CI\)\(F\)'
    $userPattern  = [regex]::Escape($FSLogixUsers)  + ':\(M\)'

    @(
        [pscustomobject]@{ Check = 'FSLogix inheritance disabled'; Result = if ($aclObj.AreAccessRulesProtected) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = 'FSLogix CREATOR OWNER Modify, subfolders/files only'; Result = if ($aclText -match 'CREATOR OWNER:\(OI\)\(CI\)\(IO\)\(M\)') { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = 'FSLogix SYSTEM Full Control'; Result = if ($aclText -match 'SYSTEM:\(OI\)\(CI\)\(F\)') { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "FSLogix admins Full Control: $FSLogixAdmins"; Result = if ($aclText -match $adminPattern) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "FSLogix users Modify, this folder only: $FSLogixUsers"; Result = if ($aclText -match $userPattern) { 'PASS' } else { 'FAIL' } }
    )
}

function Invoke-FSLogixStorage {
    if ($StorageType -eq 'WindowsFileServer') {
        $path = Join-Path (Join-Path $DriveLetter $RootFolder) $FSLogixFolder

        if ($Mode -eq 'ConfigureAndValidate') {
            Ensure-Directory -Path $path
            Ensure-SmbShare -Name $FSLogixShare -Path $path -FullAccess @($FSLogixAdmins) -ChangeAccess @($FSLogixUsers)
            Set-FSLogixAcl -Path $path
        }

        Write-Host "`nFSLogix NTFS validation:"
        Show-ValidationResult -Results (Test-FSLogixAcl -Path $path)

        Write-Host "`nFSLogix SMB share validation:"
        Get-SmbShareAccess -Name $FSLogixShare | Format-Table -AutoSize
    }
    else {
        if (-not (Test-Path $FSLogixUNC)) { throw "Cannot access FSLogix UNC: $FSLogixUNC" }

        if ($Mode -eq 'ConfigureAndValidate') {
            Set-FSLogixAcl -Path $FSLogixUNC
        }

        Write-Host "`nFSLogix NTFS validation:"
        Show-ValidationResult -Results (Test-FSLogixAcl -Path $FSLogixUNC)

        Write-Host "Nutanix Files: validate SMB share permissions separately in Prism."
    }
}

# -----------------------------
# DEM FUNCTIONS
# -----------------------------

function Set-DEMConfigAcl {
    param([Parameter(Mandatory)][string]$Path)

    Reset-NtfsInheritance -Path $Path

    icacls $Path /grant:r "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $Path /grant:r "$DEMAdmins:(OI)(CI)F" | Out-Null
    icacls $Path /grant:r "$DEMUsers:(OI)(CI)RX" | Out-Null

    if ($EnableDEMComputerEnvironmentSettingsSupport) {
        icacls $Path /grant:r "$DEMComputers:(OI)(CI)RX" | Out-Null
    }
}

function Set-DEMProfileAcl {
    param([Parameter(Mandatory)][string]$Path)

    Reset-NtfsInheritance -Path $Path

    icacls $Path /grant:r "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $Path /grant:r "$DEMAdmins:(OI)(CI)F" | Out-Null
    icacls $Path /grant:r "CREATOR OWNER:(OI)(CI)(IO)F" | Out-Null
    icacls $Path /grant:r "$DEMUsers:(AD,R,S)" | Out-Null

    if ($EnableDEMComputerEnvironmentSettingsSupport) {
        icacls $Path /grant:r "$DEMComputers:(AD,R,S)" | Out-Null
    }
}

function Test-DEMConfigAcl {
    param([Parameter(Mandatory)][string]$Path)

    $aclText = icacls $Path
    $aclObj  = Get-Acl $Path

    @(
        [pscustomobject]@{ Check = 'DEM Config inheritance disabled'; Result = if ($aclObj.AreAccessRulesProtected) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = 'DEM Config SYSTEM Full Control'; Result = if ($aclText -match 'SYSTEM:\(OI\)\(CI\)\(F\)') { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "DEM Config admins Full Control: $DEMAdmins"; Result = if ($aclText -match ([regex]::Escape($DEMAdmins) + ':\(OI\)\(CI\)\(F\)')) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "DEM Config users Read/Execute: $DEMUsers"; Result = if ($aclText -match ([regex]::Escape($DEMUsers) + ':\(OI\)\(CI\)\(RX\)')) { 'PASS' } else { 'FAIL' } }
    )
}

function Test-DEMProfileAcl {
    param([Parameter(Mandatory)][string]$Path)

    $aclText = icacls $Path
    $aclObj  = Get-Acl $Path

    @(
        [pscustomobject]@{ Check = 'DEM Profile inheritance disabled'; Result = if ($aclObj.AreAccessRulesProtected) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = 'DEM Profile CREATOR OWNER Full Control'; Result = if ($aclText -match 'CREATOR OWNER:\(OI\)\(CI\)\(IO\)\(F\)') { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "DEM Profile admins Full Control: $DEMAdmins"; Result = if ($aclText -match ([regex]::Escape($DEMAdmins) + ':\(OI\)\(CI\)\(F\)')) { 'PASS' } else { 'FAIL' } }
        [pscustomobject]@{ Check = "DEM Profile users create folder on root: $DEMUsers"; Result = if ($aclText -match ([regex]::Escape($DEMUsers) + ':\(AD,R,S\)')) { 'PASS' } else { 'FAIL' } }
    )
}

function Invoke-DEMStorage {
    if ($StorageType -eq 'WindowsFileServer') {
        $rootPath    = Join-Path $DriveLetter $RootFolder
        $configPath  = Join-Path $rootPath $DEMConfigFolder
        $profilePath = Join-Path $rootPath $DEMProfilesFolder

        if ($Mode -eq 'ConfigureAndValidate') {
            Ensure-Directory -Path $rootPath
            Ensure-Directory -Path $configPath
            Ensure-Directory -Path $profilePath

            Ensure-SmbShare -Name $DEMConfigShare -Path $configPath -FullAccess @($DEMAdmins) -ReadAccess @($DEMUsers, $DEMComputers)
            Ensure-SmbShare -Name $DEMProfilesShare -Path $profilePath -FullAccess @($DEMAdmins) -ChangeAccess @('Everyone')

            Set-DEMConfigAcl -Path $configPath
            Set-DEMProfileAcl -Path $profilePath
        }

        Write-Host "`nDEM Config NTFS validation:"
        Show-ValidationResult -Results (Test-DEMConfigAcl -Path $configPath)

        Write-Host "`nDEM Profile Archive NTFS validation:"
        Show-ValidationResult -Results (Test-DEMProfileAcl -Path $profilePath)

        Write-Host "`nDEM SMB share validation:"
        Get-SmbShareAccess -Name $DEMConfigShare | Format-Table -AutoSize
        Get-SmbShareAccess -Name $DEMProfilesShare | Format-Table -AutoSize
    }
    else {
        if (-not (Test-Path $DEMConfigUNC)) { throw "Cannot access DEM Config UNC: $DEMConfigUNC" }
        if (-not (Test-Path $DEMProfilesUNC)) { throw "Cannot access DEM Profiles UNC: $DEMProfilesUNC" }

        if ($Mode -eq 'ConfigureAndValidate') {
            Set-DEMConfigAcl -Path $DEMConfigUNC
            Set-DEMProfileAcl -Path $DEMProfilesUNC
        }

        Write-Host "`nDEM Config NTFS validation:"
        Show-ValidationResult -Results (Test-DEMConfigAcl -Path $DEMConfigUNC)

        Write-Host "`nDEM Profile Archive NTFS validation:"
        Show-ValidationResult -Results (Test-DEMProfileAcl -Path $DEMProfilesUNC)

        Write-Host "Nutanix Files: validate SMB share permissions separately in Prism."
    }
}

# -----------------------------
# MAIN
# -----------------------------

switch ($Workload) {
    'FSLogix' { Invoke-FSLogixStorage }
    'DEM'     { Invoke-DEMStorage }
    'Both'    {
        Invoke-FSLogixStorage
        Invoke-DEMStorage
    }
}

Write-Host "`nCompleted. Mode: $Mode | StorageType: $StorageType | Workload: $Workload"
