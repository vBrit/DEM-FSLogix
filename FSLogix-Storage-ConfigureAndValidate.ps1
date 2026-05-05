<#
FSLogix storage setup + validation
References:
- Microsoft FSLogix storage permissions:
  https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions
- Nutanix Files share/NTFS permissions:
  https://portal.nutanix.com/docs/Files-v5_1%3Afil-file-server-authorization-c.html
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# Options:
#   WindowsFileServer
#   NutanixFiles
$StoragePlatform = 'WindowsFileServer'

# Options:
#   ConfigureAndValidate
#   ValidateOnly
$Mode = 'ConfigureAndValidate'

# Windows File Server values
$DriveLetter  = 'C:'
$FolderName   = 'FSLogix'
$FSLogixShare = 'FSLogix'

# Nutanix Files UNC path - share must already exist
$NutanixFSLogixUNC = '\\NUTANIX-FILES-FQDN\FSLogix'

# Security groups
$FSLogixAdmins = 'DOMAIN\FSLogix-Admins'
$FSLogixUsers  = 'DOMAIN\FSLogix-Users'

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created folder: $Path"
    }
}

function Ensure-SmbShare {
    param(
        [string]$Name,
        [string]$Path
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

    if (-not (Test-Path $Path)) {
        throw "Path is not accessible: $Path"
    }

    icacls $Path /inheritance:r | Out-Null

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
    param(
        [string]$Path,
        [string]$Admins,
        [string]$Users
    )

    if (-not (Test-Path $Path)) {
        throw "Path is not accessible: $Path"
    }

    $aclText = icacls $Path
    $aclObject = Get-Acl $Path

    $checks = @()

    $checks += [pscustomobject]@{
        Check  = 'Inheritance disabled'
        Result = if ($aclObject.AreAccessRulesProtected) { 'PASS' } else { 'FAIL' }
    }

    $checks += [pscustomobject]@{
        Check  = 'CREATOR OWNER Modify - subfolders/files only'
        Result = if ($aclText -match 'CREATOR OWNER:\(OI\)\(CI\)\(IO\)\(M\)') { 'PASS' } else { 'FAIL' }
    }

    $checks += [pscustomobject]@{
        Check  = 'SYSTEM Full Control'
        Result = if ($aclText -match 'SYSTEM:\(OI\)\(CI\)\(F\)') { 'PASS' } else { 'FAIL' }
    }

    $adminPattern = [regex]::Escape($Admins) + ':\(OI\)\(CI\)\(F\)'
    $checks += [pscustomobject]@{
        Check  = "$Admins Full Control"
        Result = if ($aclText -match $adminPattern) { 'PASS' } else { 'FAIL' }
    }

    $userPattern = [regex]::Escape($Users) + ':\(M\)'
    $checks += [pscustomobject]@{
        Check  = "$Users Modify - this folder only"
        Result = if ($aclText -match $userPattern) { 'PASS' } else { 'FAIL' }
    }

    $checks
}

function Test-WindowsShareAccess {
    param([string]$ShareName)

    $shareAccess = Get-SmbShareAccess -Name $ShareName -ErrorAction Stop

    $checks = @()

    $adminAccess = $shareAccess | Where-Object {
        $_.AccountName -eq $FSLogixAdmins -and $_.AccessRight -eq 'Full'
    }

    $userAccess = $shareAccess | Where-Object {
        $_.AccountName -eq $FSLogixUsers -and $_.AccessRight -eq 'Change'
    }

    $checks += [pscustomobject]@{
        Check  = "$FSLogixAdmins SMB Full"
        Result = if ($adminAccess) { 'PASS' } else { 'FAIL' }
    }

    $checks += [pscustomobject]@{
        Check  = "$FSLogixUsers SMB Change"
        Result = if ($userAccess) { 'PASS' } else { 'FAIL' }
    }

    $checks
}

switch ($StoragePlatform) {

    'WindowsFileServer' {
        $FSLogixFolder = Join-Path $DriveLetter $FolderName

        if ($Mode -eq 'ConfigureAndValidate') {
            Ensure-Directory -Path $FSLogixFolder
            Ensure-SmbShare -Name $FSLogixShare -Path $FSLogixFolder
            Set-FSLogixAcl -Path $FSLogixFolder
        }

        Write-Host "`nNTFS validation:"
        Test-FSLogixAcl -Path $FSLogixFolder -Admins $FSLogixAdmins -Users $FSLogixUsers | Format-Table -AutoSize

        Write-Host "`nSMB share validation:"
        Test-WindowsShareAccess -ShareName $FSLogixShare | Format-Table -AutoSize

        Write-Host "`nFSLogix path: \\$env:COMPUTERNAME\$FSLogixShare"
    }

    'NutanixFiles' {
        if (-not (Test-Path $NutanixFSLogixUNC)) {
            throw "Cannot access Nutanix Files UNC path: $NutanixFSLogixUNC"
        }

        if ($Mode -eq 'ConfigureAndValidate') {
            Set-FSLogixAcl -Path $NutanixFSLogixUNC
        }

        Write-Host "`nNTFS validation:"
        Test-FSLogixAcl -Path $NutanixFSLogixUNC -Admins $FSLogixAdmins -Users $FSLogixUsers | Format-Table -AutoSize

        Write-Host "`nNutanix Files reminder:"
        Write-Host "Validate SMB share-level permissions separately in Prism / Files Console."
        Write-Host "Expected: admins Full Control, FSLogix users Change/Modify equivalent."

        Write-Host "`nFSLogix path: $NutanixFSLogixUNC"
    }

    default {
        throw "Invalid StoragePlatform. Use WindowsFileServer or NutanixFiles."
    }
}
