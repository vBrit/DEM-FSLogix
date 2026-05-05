<#
.SYNOPSIS
Creates or configures FSLogix storage for Windows File Server or Nutanix Files, then validates permissions.

.EXAMPLE
.\FSLogix-Storage-MultiPlatform.ps1 -StorageType WindowsFileServer

.EXAMPLE
.\FSLogix-Storage-MultiPlatform.ps1 -StorageType NutanixFiles
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('WindowsFileServer','NutanixFiles')]
    [string]$StorageType
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# -----------------------------
# CONFIGURATION
# -----------------------------

$DriveLetter  = 'C:'
$FolderName   = 'FSLogix'
$FSLogixShare = 'FSLogix'

$NutanixFSLogixUNC = '\\NUTANIX-FILES-FQDN\FSLogix'

$FSLogixAdmins = 'DOMAIN\FSLogix-Admins'
$FSLogixUsers  = 'DOMAIN\FSLogix-Users'

# -----------------------------
# FUNCTIONS
# -----------------------------

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created folder: $Path"
    }
}

function Ensure-SmbShare {
    param([string]$Name,[string]$Path)

    $share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue

    if ($share) {
        Set-SmbShare -Name $Name -CachingMode None -FolderEnumerationMode AccessBased -Force | Out-Null
    }
    else {
        New-SmbShare -Name $Name `
            -Path $Path `
            -FullAccess $FSLogixAdmins `
            -ChangeAccess $FSLogixUsers `
            -CachingMode None `
            -FolderEnumerationMode AccessBased | Out-Null
    }
}

function Set-FSLogixAcl {
    param([string]$Path)

    icacls $Path /inheritance:r | Out-Null

    icacls $Path /grant:r "CREATOR OWNER:(OI)(CI)(IO)(M)" | Out-Null
    icacls $Path /grant:r "SYSTEM:(OI)(CI)(F)" | Out-Null
    icacls $Path /grant:r "$FSLogixAdmins:(OI)(CI)(F)" | Out-Null
    icacls $Path /grant:r "$FSLogixUsers:(M)" | Out-Null
}

function Test-FSLogixAcl {
    param([string]$Path)

    $acl = icacls $Path
    $aclObj = Get-Acl $Path

    @(
        "Inheritance: $($aclObj.AreAccessRulesProtected)"
        "CREATOR OWNER: $(if ($acl -match 'CREATOR OWNER') {'OK'} else {'FAIL'})"
        "Admins: $(if ($acl -match $FSLogixAdmins) {'OK'} else {'FAIL'})"
        "Users: $(if ($acl -match $FSLogixUsers) {'OK'} else {'FAIL'})"
    )
}

function Test-WindowsShareAccess {
    param([string]$Share)

    Get-SmbShareAccess -Name $Share | Select AccountName,AccessRight
}

# -----------------------------
# MAIN
# -----------------------------

switch ($StorageType) {

    'WindowsFileServer' {

        $Path = Join-Path $DriveLetter $FolderName

        Ensure-Directory $Path
        Ensure-SmbShare $FSLogixShare $Path
        Set-FSLogixAcl $Path

        Write-Host "`nValidation:"
        Test-FSLogixAcl $Path

        Write-Host "`nShare Permissions:"
        Test-WindowsShareAccess $FSLogixShare

        Write-Host "`nPath: \\$env:COMPUTERNAME\$FSLogixShare"
    }

    'NutanixFiles' {

        if (-not (Test-Path $NutanixFSLogixUNC)) {
            throw "Cannot access $NutanixFSLogixUNC"
        }

        Set-FSLogixAcl $NutanixFSLogixUNC

        Write-Host "`nValidation:"
        Test-FSLogixAcl $NutanixFSLogixUNC

        Write-Host "`nNOTE: Validate share permissions in Nutanix Prism."
    }
}
