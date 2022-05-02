<#
This Script Creates a folder that will be used by FSLogix and applies the Share and NTFS permissions
Karl Newick
www.vbrit.net
#>
$DriveLetter = 'C:'
$FolderName = 'FSLogix'
$FSLogixShare = 'FSLogixTest'
$FSLogixAdmins = 'Horizon View Admins'
$FSLogixUsers = 'FSLogix - Office 365 Containers'

<#
Do not edit below
#>

mkdir "$DriveLetter\$FolderName"

$FSLogixFolder = "$DriveLetter\$FolderName"

# Create Share and Apply Permissions

New-SMBShare -Name "$FSLogixShare" `
             -Path "$FSLogixFolder" `
             -FullAccess "$FSLogixAdmins" `
             -ChangeAccess "$FSLogixUsers" `
             -CachingMode None `
             -FolderEnumerationMode AccessBased


#Clear all Explicit Permissions on the folder
ICACLS ("$FSLogixFolder") /reset

#Add CREATOR OWNER permission
ICACLS ("$FSLogixFolder") /grant ("CREATOR OWNER" + ':(OI)(CI)(IO)F')

#Add SYSTEM permission
ICACLS ("$FSLogixFolder") /grant ("SYSTEM" + ':(OI)(CI)F')

#Give Domain Admins Full Control
ICACLS ("$FSLogixFolder") /grant ("$FSLogixAdmins" + ':(OI)(CI)F')

#Apply Create Folder/Append Data, List Folder/Read Data, Read Attributes, Traverse Folder/Execute File, Read permissions to this folder only. Synchronize is required in order for the permissions to work
ICACLS ("$FSLogixFolder") /grant ("$FSLogixUsers" + ':(AD,REA,RA,X,RC,RD,S)')

#Disable Inheritance on the Folder. This is done last to avoid permission errors.
ICACLS ("$FSLogixFolder") /inheritance:r