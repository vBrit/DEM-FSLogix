<#
.SYNOPSIS
Creates or configures FSLogix storage for Windows File Server or Nutanix Files.

.DESCRIPTION
Supports:
  - WindowsFileServer: creates local folder, SMB share, and NTFS ACLs.
  - NutanixFiles: applies NTFS ACLs to an existing Nutanix Files SMB UNC path.

Microsoft FSLogix reference:
https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions

Nutanix Files reference:
https://portal.nutanix.com/docs/Nutanix-Files-v5_2%3Afil-file-server-authorization-c.html
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

# Windows File Server values
$DriveLetter    = 'C:'
$FolderName     = 'FSLogix'
$FSLogixShare   = 'FSLogix'

# Nutanix Files UNC path
# Share must already exist in Prism / Nutanix Files.
$NutanixFSLogixUNC = '\\NUTANIX-FILES-FQDN\FSLogix'

# Recommended: use dedicated AD groups.
$FSLogixAdmins = 'DOMAIN\FSLogix-Admins'
$FSLogixUsers  = 'DOMAIN\FSLogix-Users'

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
        [string]$Path
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
        New-SmbShare -Name $Name `
            -Path $Path `
            -FullAccess $FSLogixAdmins `
            -ChangeAccess $FSLogixUsers `
            -CachingMode None `
            -FolderEnumerationMode AccessBased | Out-Null

        Write-Host "Created SMB share: $Name"
    }
}

function Set-FSLogixAcl {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Path is not accessible: $Path"
    }

    Write-Host "Applying Microsoft-recommended FSLogix NTFS permissions to: $Path"

    # Disable inheritance and remove inherited permissions.
    icacls $Path /inheritance:r | Out-Null

    # Remove common existing explicit permissions where possible.
    icacls $Path /remove:g "$FSLogixUsers" 2>$null | Out-Null
    icacls $Path /remove:g "$FSLogixAdmins" 2>$null | Out-Null
    icacls $Path /remove:g "CREATOR OWNER" 2>$null | Out-Null
    icacls $Path /remove:g "SYSTEM" 2>$null | Out-Null

    # Microsoft FSLogix recommended NTFS ACLs.
    # CREATOR OWNER: Modify, subfolders and files only.
    icacls $Path /grant:r "CREATOR OWNER:(OI)(CI)(IO)(M)" | Out-Null

    # SYSTEM: Full Control, this folder, subfolders and files.
    icacls $Path /grant:r "SYSTEM:(OI)(CI)(F)" | Out-Null

    # Admins: Full Control, this folder, subfolders and files.
    icacls $Path /grant:r "$FSLogixAdmins:(OI)(CI)(F)" | Out-Null

    # Users: Modify, this folder only.
    icacls $Path /grant:r "$FSLogixUsers:(M)" | Out-Null

    Write-Host "FSLogix NTFS ACLs applied successfully."
}

# -----------------------------
# MAIN
# -----------------------------

switch ($StoragePlatform) {

    'WindowsFileServer' {

        $FSLogixFolder = Join-Path $DriveLetter $FolderName

        Ensure-Directory -Path $FSLogixFolder
        Ensure-SmbShare -Name $FSLogixShare -Path $FSLogixFolder
        Set-FSLogixAcl -Path $FSLogixFolder

        Write-Host "`nCompleted Windows File Server FSLogix configuration."
        Write-Host "FSLogix share path: \\$env:COMPUTERNAME\$FSLogixShare"
    }

    'NutanixFiles' {

        Write-Host "Nutanix Files mode selected."
        Write-Host "Skipping Windows SMB share creation. Create the share first in Prism / Nutanix Files."

        if (-not (Test-Path -Path $NutanixFSLogixUNC)) {
            throw "Cannot access Nutanix Files UNC path: $NutanixFSLogixUNC"
        }

        Set-FSLogixAcl -Path $NutanixFSLogixUNC

        Write-Host "`nCompleted Nutanix Files FSLogix NTFS ACL configuration."
        Write-Host "FSLogix share path: $NutanixFSLogixUNC"
        Write-Host "Reminder: configure Nutanix SMB share-level permissions separately."
    }

    default {
        throw "Invalid StoragePlatform value. Use 'WindowsFileServer' or 'NutanixFiles'."
    }
}
