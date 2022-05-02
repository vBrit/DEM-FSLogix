<#
This Script Creates a folder that will be used by FSLogix and applies the 
Share and NTFS permissions base on Security Groups
Karl Newick 
www.vbrit.net
#>
$DriveLetter = 'C:'
$FolderConfiguration = 'Configuration'
$ConfigShareName = 'DEM-Config'
$FolderProfiles = 'Profiles'
$ProfileShareName = 'DEM-Profile'
$DEMAdmins = 'DEM - Admins'
$DEMUsers = 'Domain Users'
$DEMComputers = 'Domain Computers'

<#
Do not Edit below
#>

mkdir "$DriveLetter\DEM\$FolderConfiguration"

$DEMConfigurationDirectory = "$DriveLetter\DEM\$FolderConfiguration"

# Create Share and Apply Permissions

New-SMBShare -Name "$ConfigShareName" `
    -Path "$DEMConfigurationDirectory" `
    -FullAccess "$DEMAdmins" `
    -ReadAccess "$DEMUsers", "$DEMComputers" `
    -CachingMode None

#Clear all Explicit Permissions on the folder
ICACLS ("$DEMConfigurationDirectory") /reset

#Give Domain Admins Full Control
ICACLS ("$DEMConfigurationDirectory") /grant ("$DEMAdmins" + ':(OI)(CI)F')

#Give Domain Users and Domain Computers Read Access
ICACLS ("$DEMConfigurationDirectory") /grant ("$DEMComputers" + ':(OI)(CI)(RX,RA,RC,RD,S)')
ICACLS ("$DEMConfigurationDirectory") /grant ("$DEMUsers" + ':(OI)(CI)(RX,RA,RC,RD,S)')

#Disable Inheritance on the Folder. This is done last to avoid permission errors.
ICACLS ("$DEMConfigurationDirectory") /inheritance:r

# Create Profiles Share and Apply Permissions

mkdir "$DriveLetter\DEM\$FolderProfiles"

$DEMProfilesDirectory = "$DriveLetter\DEM\$FolderProfiles"

New-SMBShare -Name "$ProfileShareName" `
    -Path "$DEMProfilesDirectory" `
    -FullAccess "$DEMAdmins", "$DEMUsers" `
    -CachingMode None `
    -FolderEnumerationMode AccessBased

#Clear all Explicit Permissions on the folder
ICACLS ("$DEMProfilesDirectory") /reset

#Add CREATOR OWNER permission
ICACLS ("$DEMProfilesDirectory") /grant ("CREATOR OWNER" + ':(OI)(CI)(IO)F')

#Add SYSTEM permission
ICACLS ("$DEMProfilesDirectory") /grant ("SYSTEM" + ':(OI)(CI)F')

#Give Domain Admins Full Control
ICACLS ("$DEMProfilesDirectory") /grant ("$DEMAdmins" + ':(OI)(CI)F')

#Apply Create Folder/Append Data, List Folder/Read Data, Read Attributes, Traverse Folder/Execute File, Read permissions to this folder only. Synchronize is required in order for the permissions to work
ICACLS ("$DEMProfilesDirectory") /grant ("$DEMUsers" + ':(AD,R,S)')

#Disable Inheritance on the Folder. This is done last to avoid permission errors.
ICACLS ("$DEMProfilesDirectory") /inheritance:r