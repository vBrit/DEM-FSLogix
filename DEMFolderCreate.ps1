<#
.SYNOPSIS
Creates or configures Omnissa DEM Configuration and Profile Archive shares.

.DESCRIPTION
Supports:
  - Windows File Server
  - Nutanix Files SMB shares

Omnissa references:
  Dynamic Environment Manager Configuration Share:
  https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/DynamicEnvironmentManagerConfigurationShare.html

  Profile Archives Share:
  https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/ProfileArchivesShare.html

Nutanix reference:
  Nutanix Files Share and Export Permissions:
  https://portal.nutanix.com/docs/Files-v5_1%3Afil-file-server-authorization-c.html
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# -----------------------------
# CUSTOMISE THESE VALUES
# -----------------------------

# Options:
#   WindowsFileServer
#   NutanixFiles
$StoragePlatform = 'WindowsFileServer'

# Windows File Server local paths
$DriveLetter = 'C:'
$RootFolder  = 'DEM'

$FolderConfiguration = 'Configuration'
$FolderProfiles      = 'Profiles'

$ConfigShareName  = 'DEM-Config'
$ProfileShareName = 'DEM-Profile'

# Nutanix Files UNC paths.
# These shares must already exist on Nutanix Files.
$NutanixConfigUNC   = '\\NUTANIX-FILES-FQDN\DEM-Config'
$NutanixProfilesUNC = '\\NUTANIX-FILES-FQDN\DEM-Profile'

# Recommended: use dedicated AD security groups.
$DEMAdmins    = 'DOMAIN\DEM-Admins'
$DEMUsers     = 'DOMAIN\DEM-Users'
$DEMComputers = 'DOMAIN\DEM-Computers'

# Required if using DEM Computer Environment Settings / computer-based DEM settings.
$EnableComputerEnvironmentSettingsSupport = $true

# -----------------------------
# FUNCTIONS
# -----------------------------

function Ensure-Directory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created folder: $Path"
    }
    else {
        Write-Host "Folder already exists: $Path"
    }
}

function Ensure-SmbShare {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$FullAccess,

        [string[]]$ChangeAccess,

        [string[]]$ReadAccess
    )

    $existingShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue

    if ($existingShare) {
        Write-Host "SMB share already exists: $Name"

        if ($existingShare.Path -ne $Path) {
            throw "Share '$Name' already exists but points to '$($existingShare.Path)' instead of '$Path'."
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
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Resetting NTFS permissions on: $Path"
    icacls $Path /reset | Out-Null

    Write-Host "Disabling inheritance on: $Path"
    icacls $Path /inheritance:r | Out-Null
}

function Set-DemConfigShareAcl {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Reset-NtfsInheritance -Path $Path

    icacls $Path /grant "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $Path /grant "$DEMAdmins:(OI)(CI)F" | Out-Null
    icacls $Path /grant "$DEMUsers:(OI)(CI)RX" | Out-Null

    if ($EnableComputerEnvironmentSettingsSupport) {
        icacls $Path /grant "$DEMComputers:(OI)(CI)RX" | Out-Null
    }

    Write-Host "DEM Configuration NTFS ACLs applied to: $Path"
}

function Set-DemProfileArchiveAcl {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Reset-NtfsInheritance -Path $Path

    icacls $Path /grant "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $Path /grant "$DEMAdmins:(OI)(CI)F" | Out-Null
    icacls $Path /grant "CREATOR OWNER:(OI)(CI)(IO)F" | Out-Null

    # This folder only:
    # Allows users to create their own profile archive folder.
    icacls $Path /grant "$DEMUsers:(AD,R,S)" | Out-Null

    if ($EnableComputerEnvironmentSettingsSupport) {
        icacls $Path /grant "$DEMComputers:(AD,R,S)" | Out-Null
    }

    Write-Host "DEM Profile Archive NTFS ACLs applied to: $Path"
}

# -----------------------------
# MAIN
# -----------------------------

switch ($StoragePlatform) {

    'WindowsFileServer' {

        $DEMRootDirectory          = Join-Path $DriveLetter $RootFolder
        $DEMConfigurationDirectory = Join-Path $DEMRootDirectory $FolderConfiguration
        $DEMProfilesDirectory      = Join-Path $DEMRootDirectory $FolderProfiles

        Ensure-Directory -Path $DEMRootDirectory
        Ensure-Directory -Path $DEMConfigurationDirectory
        Ensure-Directory -Path $DEMProfilesDirectory

        Ensure-SmbShare `
            -Name $ConfigShareName `
            -Path $DEMConfigurationDirectory `
            -FullAccess @($DEMAdmins) `
            -ReadAccess @($DEMUsers, $DEMComputers)

        Set-DemConfigShareAcl -Path $DEMConfigurationDirectory

        Ensure-SmbShare `
            -Name $ProfileShareName `
            -Path $DEMProfilesDirectory `
            -FullAccess @($DEMAdmins) `
            -ChangeAccess @('Everyone')

        Set-DemProfileArchiveAcl -Path $DEMProfilesDirectory

        Write-Host "`nCompleted Windows File Server DEM share configuration."
        Write-Host "Configuration share: \\$env:COMPUTERNAME\$ConfigShareName"
        Write-Host "Profile archive share: \\$env:COMPUTERNAME\$ProfileShareName"
    }

    'NutanixFiles' {

        Write-Host "Nutanix Files mode selected."
        Write-Host "Skipping New-SmbShare / Set-SmbShare because shares must be created in Nutanix Files."

        if (-not (Test-Path $NutanixConfigUNC)) {
            throw "Cannot access Nutanix DEM Configuration UNC path: $NutanixConfigUNC"
        }

        if (-not (Test-Path $NutanixProfilesUNC)) {
            throw "Cannot access Nutanix DEM Profile Archive UNC path: $NutanixProfilesUNC"
        }

        Set-DemConfigShareAcl -Path $NutanixConfigUNC
        Set-DemProfileArchiveAcl -Path $NutanixProfilesUNC

        Write-Host "`nCompleted Nutanix Files DEM NTFS ACL configuration."
        Write-Host "Configuration share: $NutanixConfigUNC"
        Write-Host "Profile archive share: $NutanixProfilesUNC"
        Write-Host "Reminder: configure SMB share-level permissions in Nutanix Files / Prism."
    }

    default {
        throw "Invalid StoragePlatform value. Use 'WindowsFileServer' or 'NutanixFiles'."
    }
}
