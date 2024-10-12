<#
.DESCRIPTION
This script hives, modifies and unhives the NTUSER.DAT file

.NOTES
   Version:			0.1
   Creation Date:	07.12.2023
   Author:			Ákos Bakos
   Company:			SmartCon GmbH
   Contact:			akos.bakos@smartcon.ch

   Copyright (c) 2024 SmartCon GmbH

HISTORY:
Date			By			Comments
----------		---			----------------------------------------------------------
07.12.2023		Ákos Bakos	Script created
26.02.2024      Akos Bakos  Added Microsoft Office settings, DisableTaskMgr, SettingsPageVisibility
27.02.2024      Akos Bakos  Added Microsoft Outlook 2016 Ribbon settings

#>

$Global:Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-SetDefaultHKU.log"
Start-Transcript -Path (Join-Path "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\" $Global:Transcript) -ErrorAction Ignore | Out-Null

Function Set-RegistryKey {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Key,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        $Value,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'None', 'QWord', 'String', 'Unknown')]
        [Microsoft.Win32.RegistryValueKind]$Type = 'String'
    )
    
    if (!(Get-Item $Key -ErrorAction SilentlyContinue)) {
        $null = New-Item $Key -Force
    }
    
    Write-Host "Set registry key value: [$Key] [$Name = $Value] with [$Type]."
    $null = New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue
    $Target = Get-ItemPropertyValue $Key -Name $Name
    
    If ($Target) {
        Write-Host "Successfully created"
        Write-Host ""
    }
}
    
Function Import-RegistryHive {
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory = $true)]$File,
        # check the registry key name is not an invalid format
        [String][Parameter(Mandatory = $true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        # check the PSDrive name does not include invalid characters
        [String][Parameter(Mandatory = $true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )
    
    # check whether the drive name is available
    $TestDrive = Get-PSDrive -Name $Name -EA SilentlyContinue
    if ($TestDrive -ne $null) {
        throw [Management.Automation.SessionStateException] "A drive with the name '$Name' already exists."
    }
    
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait
    
    if ($Process.ExitCode) {
        throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load. Verify the source path or target registry key."
    }
    
    try {
        # validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch {
        throw [Management.Automation.PSInvalidOperationException] "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
    }
}
    
Function Remove-RegistryHive {
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory = $true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )
    
    # set -ErrorAction Stop as we never want to proceed if the drive doesnt exist
    $Drive = Get-PSDrive -Name $Name -EA Stop
    # $Drive.Root is the path to the registry key, save this before the drive is removed
    $Key = $Drive.Root
    
    # remove the drive, the only reason this should fail is if the reasource is busy
    Remove-PSDrive $Name -EA Stop
    
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode) {
        # if "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
        throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}
    
Write-Host "Load the NTUSER.DAT into HKLM\TEMP_HIVE, this can be accessed using the PSDrive TempHive"
Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\TEMP_HIVE' -Name TempHive

Write-Host "## Administrative Tools - Control Panel Settings ##"
Write-Host "# Prohibit access to Control Panel and PC settings #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoControlPanel'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Desktop Settings ##"
Write-Host "# Do not add shares of recently opened documents to Network Locations #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoRecentDocsNetHood'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Properties from the Recycle Bin context menu #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoPropertiesRecycleBin'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Recycle Bin icon from desktop #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum'
    Name  = '{645FF040-5081-101B-9F08-00AA002F954E}'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Start Menu and Taskbar Settings ##"
Write-Host "# Clear history of recently opened documents on exit #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'ClearRecentDocsOnExit'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Logoff on the Start Menu #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'StartMenuLogOff'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Run menu from Start Menu #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoRun'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## System Settings ##"
Write-Host "# Prevent access to registry editing tools #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    Name  = 'DisableRegistryTools'
    Value = '2'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Prevent access to the command prompt #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Policies\Microsoft\Windows\System'
    Name  = 'DisableCMD'
    Value = '2'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## System > Ctrl+Alt+Del Options Settings ##"
Write-Host "# Remove Lock Computer #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    Name  = 'DisableLockWorkstation'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Logoff #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoLogoff'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Remove Task Manager #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    Name  = 'DisableTaskMgr'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Windows Components > File Explorer Settings ##"
Write-Host "# Hide these specified drives in My Computer #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoDrives'
    Value = '4'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# DO NOT - Prevent access to drives from My Computer #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoViewOnDrive'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Do not move deleted files to the Recycle Bin #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'NoRecycleFiles'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Microsoft Access 2016 - Application Settings > General ##"
Write-Host "# Number of files in the Recent list (User) #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\access\File MRU'
    Name  = 'Max Display'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Microsoft Excel 2016 - Excel Options > Save ##"
Write-Host "# Default file location #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\excel\options'
    Name  = 'DefaultPath'
    Value = '%userprofile%\Desktop\Pruefungsordner\Loesungsordner'
    Type  = 'ExpandString'
}
Set-RegistryKey @Params

Write-Host "## Excel Options > Save ##"
Write-Host "# AutoRecover save location #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\excel\options'
    Name  = 'AutoRecoverPath'
    Value = '%userprofile%\Desktop\Pruefungsordner\OfficeRecovery'
    Type  = 'ExpandString'
}
Set-RegistryKey @Params

Write-Host "# Save AutoRecover info every (minutes) #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\excel\options'
    Name  = 'AutoRecoverTime'
    Value = '3'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Default file format #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\excel\options'
    Name  = 'defaultformat'
    Value = '51'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Excel Options > Advanced ##"
Write-Host "# Number of workbooks in the Recent Workbooks list #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\excel\File MRU'
    Name  = 'Max Display'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Microsoft Office 2016 > Miscellaneous ##"
Write-Host "# Hide file locations when opening or saving files #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\common\internet'
    Name  = 'onlinestorage'
    Value = '3'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Microsoft PowerPoint 2016 - PowerPoint Options > Save ##"
Write-Host "# AutoRecover save frequency (minutes) #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\powerpoint\options'
    Name  = 'FrequencyToSaveAutoRecoverInfo'
    Value = '3'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# AutoRecover save location #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\powerpoint\options'
    Name  = 'PathToAutoRecoveryInfo'
    Value = '%userprofile%\Desktop\Pruefungsordner\OfficeRecovery'
    Type  = 'String'
}
Set-RegistryKey @Params

Write-Host "# Default file format #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\powerpoint\options'
    Name  = 'defaultformat'
    Value = '27'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Default file location #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\powerpoint\RecentFolderList'
    Name  = 'Default'
    Value = '%userprofile%\Desktop\Pruefungsordner\Loesungsordner'
    Type  = 'ExpandString'
}
Set-RegistryKey @Params

Write-Host "## PowerPoint Options > Advanced ##"
Write-Host "# Size of recently used file list #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\powerpoint\File MRU'
    Name  = 'Max Display'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Microsoft Word 2016 - Word Options > Save ##"
Write-Host "# Save AutoRecover info every (minutes) #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\options'
    Name  = 'autosaveinterval'
    Value = '3'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "# Default file format #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\options'
    Name  = 'defaultformat'
    Value = ''
    Type  = 'String'
}
Set-RegistryKey @Params

Write-Host "## Word Options > Customize Ribbon ##"
Write-Host "# Display Developer tab in the Ribbon #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\options'
    Name  = 'developertools'
    Value = '1'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Word Options > Advanced ##"
Write-Host "# Number of entries #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\File MRU'
    Name  = 'Max Display'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

Write-Host "## Word Options > Advanced > File Locations ##"
Write-Host "# AutoRecover files #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\options'
    Name  = 'autosave-path'
    Value = '%userprofile%\Desktop\Pruefungsordner\OfficeRecovery'
    Type  = 'ExpandString'
}
Set-RegistryKey @Params

Write-Host "# Default File Location #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\software\policies\microsoft\office\16.0\word\options'
    Name  = 'doc-path'
    Value = '%userprofile%\Desktop\Pruefungsordner\Loesungsordner'
    Type  = 'ExpandString'
}
Set-RegistryKey @Params

Write-Host "## Settings ##"
Write-Host "# Page Visibility List #"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Name  = 'SettingsPageVisibility'
    Value = 'showonly:printers'
    Type  = 'String'
}
Set-RegistryKey @Params

Write-Host "## Microsoft Outlook 2016 Ribbon Settings ##"
$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Office\16.0\Common\Toolbars\Outlook'
    Name  = 'QuickAccessToolbarStyleExplorer'
    Value = '16'
    Type  = 'DWord'
}
Set-RegistryKey @Params

$Params = @{
    Key   = 'HKLM:\TEMP_HIVE\Software\Microsoft\Office\16.0\Outlook\Preferences'
    Name  = 'EnableSingleLineRibbon'
    Value = '0'
    Type  = 'DWord'
}
Set-RegistryKey @Params

# Attempt Remove-RegistryHive a maximum of 3 times
$attempt = 0
while ($true) {
    try {
        # When Remove-RegistryHive is successful break will stop the loop
        $attempt++
        Remove-RegistryHive -Name TempHive
        Write-Host "NTUSER.DAT updated successfully!"
        break
    }
    catch {
        if ($attempt -eq 3) {
            Write-Host "CATCH: Rethrow the exception, we gave up"
            throw
        }
    
        Write-Host "CATCH: Remove-RegistryHive failed, trying again..."
        Write-Host "CATCH: Wait for 100ms and trigger the garbage collector"
        Start-Sleep -Milliseconds 100
    
        # https://stackoverflow.com/questions/25438409/reg-unload-and-new-key
        [gc]::Collect()
    
        # Optional, and beware of deadlocks! Only seen this needed in Debug mode.
        # [gc]::WaitForPendingFinalizers()
    }
}

Stop-Transcript -Verbose | Out-Null