<#
.SYNOPSIS
Creates Omnissa Dynamic Environment Manager configuration and profile archive shares.

.DESCRIPTION
Creates:
  - DEM Configuration share
  - DEM Profile Archives share

Aligned to Omnissa DEM Install and Configuration Guide v2603:
  - Dynamic Environment Manager Configuration Share
    https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/DynamicEnvironmentManagerConfigurationShare.html

  - Profile Archives Share
    https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/ProfileArchivesShare.html

.NOTES
Run from an elevated PowerShell session on the file server.

Update the variables in the "CUSTOMISE THESE VALUES" section before running.
#>

#Requires -RunAsAdministrator

# -----------------------------
# CUSTOMISE THESE VALUES
# -----------------------------

$DriveLetter        = 'C:'
$RootFolder         = 'DEM'

$FolderConfiguration = 'Configuration'
$ConfigShareName     = 'DEM-Config'

$FolderProfiles    = 'Profiles'
$ProfileShareName  = 'DEM-Profile'

# Recommended: replace broad built-in/domain groups with dedicated AD security groups.
$DEMAdmins    = 'DEM - Admins'
$DEMUsers     = 'Domain Users'
$DEMComputers = 'Domain Computers'

# Set to $true only if you use DEM Computer Environment Settings.
$EnableComputerEnvironmentSettingsSupport = $true

# -----------------------------
# DO NOT EDIT BELOW UNLESS NEEDED
# -----------------------------

$ErrorActionPreference = 'Stop'

$DEMRootDirectory          = Join-Path $DriveLetter $RootFolder
$DEMConfigurationDirectory = Join-Path $DEMRootDirectory $FolderConfiguration
$DEMProfilesDirectory      = Join-Path $DEMRootDirectory $FolderProfiles

function Test-LocalAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

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

function Reset-NtfsInheritance {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Resetting NTFS permissions on: $Path"
    icacls $Path /reset | Out-Null

    Write-Host "Removing inherited permissions on: $Path"
    icacls $Path /inheritance:r | Out-Null
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

        if ($FullAccess)  { $params.FullAccess  = $FullAccess }
        if ($ChangeAccess){ $params.ChangeAccess = $ChangeAccess }
        if ($ReadAccess)  { $params.ReadAccess  = $ReadAccess }

        New-SmbShare @params | Out-Null
        Write-Host "Created SMB share: $Name"
    }
}

if (-not (Test-LocalAdmin)) {
    throw "This script must be run from an elevated PowerShell session."
}

Write-Host "Creating DEM folder structure..."

Ensure-Directory -Path $DEMRootDirectory
Ensure-Directory -Path $DEMConfigurationDirectory
Ensure-Directory -Path $DEMProfilesDirectory

# ----------------------------------------------------
# DEM Configuration Share
# Omnissa requirement:
#   - DEM administrators: Full Control
#   - DEM users: Read access
#   - DEM computers: Read access when computer settings are used
#   - Offline caching disabled
# ----------------------------------------------------

Write-Host "`nConfiguring DEM Configuration share..."

Ensure-SmbShare `
    -Name $ConfigShareName `
    -Path $DEMConfigurationDirectory `
    -FullAccess @($DEMAdmins) `
    -ReadAccess @($DEMUsers, $DEMComputers)

Reset-NtfsInheritance -Path $DEMConfigurationDirectory

icacls $DEMConfigurationDirectory /grant "$DEMAdmins:(OI)(CI)F" | Out-Null
icacls $DEMConfigurationDirectory /grant "$DEMUsers:(OI)(CI)RX" | Out-Null
icacls $DEMConfigurationDirectory /grant "$DEMComputers:(OI)(CI)RX" | Out-Null

Write-Host "DEM Configuration share configured successfully."

# ----------------------------------------------------
# DEM Profile Archives Share
# Omnissa requirement:
#   - Users need to create their own profile archive folder
#   - CREATOR OWNER owns/manages created folders
#   - Administrators have Full Control
#   - Offline caching disabled
# ----------------------------------------------------

Write-Host "`nConfiguring DEM Profile Archives share..."

Ensure-SmbShare `
    -Name $ProfileShareName `
    -Path $DEMProfilesDirectory `
    -FullAccess @($DEMAdmins) `
    -ChangeAccess @('Everyone')

Reset-NtfsInheritance -Path $DEMProfilesDirectory

icacls $DEMProfilesDirectory /grant "SYSTEM:(OI)(CI)F" | Out-Null
icacls $DEMProfilesDirectory /grant "$DEMAdmins:(OI)(CI)F" | Out-Null
icacls $DEMProfilesDirectory /grant "CREATOR OWNER:(OI)(CI)(IO)F" | Out-Null

# This folder only:
# Users can create their own profile archive folder, list the root, read attributes, traverse, and synchronize.
icacls $DEMProfilesDirectory /grant "$DEMUsers:(AD,R,S)" | Out-Null

if ($EnableComputerEnvironmentSettingsSupport) {
    # Required when DEM Computer Environment Settings are used.
    icacls $DEMProfilesDirectory /grant "$DEMComputers:(AD,R,S)" | Out-Null
    Write-Host "Computer Environment Settings support enabled for profile archive root."
}

Write-Host "DEM Profile Archives share configured successfully."

Write-Host "`nCompleted successfully."
Write-Host "Configuration share path: \\$env:COMPUTERNAME\$ConfigShareName"
Write-Host "Profile archive share path: \\$env:COMPUTERNAME\$ProfileShareName"
