<#
.SYNOPSIS
Remediate script about user profile deletion for *student* accounts

.NOTES
   Version:			  0.1
   Creation Date:	05-06-2023
   Author:			  Ákos Bakos
   Company:			  SmartCon GmbH
   Contact:			  akos.bakos@smartcon.ch

   Copyright (c) 2023 SmartCon GmbH

HISTORY:
Date			By			    Comments
----------		---			    ----------------------------------------------------------
05.06.2023      Akos Bakos      Script created
20.11.2023      Akos Bakos      Scheduled task extended with 'Clear-RecycleBin'
29.11.2023      Akos Bakos      New 'Clear-RecycleBin' command + new versioning
30.11.2023      Akos Bakos      Adding the shutdown tigger (event id 1)

#>

# scheduled task version
[int32]$Version = "4"

Function StartScript {

    $scriptFolderPath = "$env:SystemDrive\Scripts"
    $userConfigScriptPath = $(Join-Path -Path $scriptFolderPath -ChildPath "RemoveUserProfile_Script.ps1")

    If(!(Test-Path -Path $scriptFolderPath)) {
        New-Item -Path $scriptFolderPath -ItemType Directory -Force | Out-Null
    }

    Write-Host "Block inheritence for $scriptFolderPath"
    $Acl = Get-Acl $scriptFolderPath
    $Acl.SetAccessRuleProtection($true,$false)
    $Acl | Set-Acl $scriptFolderPath

    Write-Host "Getting Administrators group SID"
    $SID_Admins = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount])

    Write-Host "Set ACL for Admins on $scriptFolderPath"
    $Acl = Get-Acl $scriptFolderPath
    $AccessRuleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule($SID_Admins, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($AccessRuleAdmins)
    $Acl | Set-Acl $scriptFolderPath

    Write-Host "Getting SYSTEM SID"
    $SID_system = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")).Translate([System.Security.Principal.NTAccount])

    Write-Host "Set ACL for SYSTEM on $scriptFolderPath"
    $Acl = Get-Acl $scriptFolderPath
    $AccessRuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule($SID_System, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($AccessRuleSystem)
    $Acl | Set-Acl $scriptFolderPath

    $userConfigScript = @"
    <#
    .SYNOPSIS
       Delete user profiles on local or remote computer, the session in which you are running the script must be started with elevated user rights (Run as Administrator).
    .DESCRIPTION
       This script delete the user profiles on local o remote computer that match the search criteria.
    .PARAMETER UserName
        User Name to delete user profile, is possible use the '*' wildchar.
    .PARAMETER ExcludeUserName
        User name to exclude, is possible use the '*' wildchar.
    .PARAMETER InactiveDays
        Inactive days of the profile, this parameter is optional and specify that the profile will be deleted only if not used for the specifed days.
    .PARAMETER ComputerName
        Host name or list of host names on witch delete user profile, this parameter is optional (the default value is local computer).
    .PARAMETER IncludeSpecialUsers
        Include also special system service in the search, this parameter is optional (the default value is False).
    .PARAMETER Force
        Force execution without require confirm (the default value is False).
    .EXAMPLE
        ./Remove-UserProfile.ps1 -UserName "LoganJ"
        Delete the profile of the user with user name equal LoganJ.
    .EXAMPLE
        ./Remove-UserProfile.ps1 -UserName "Logan*"
        Delete all user profiles of the user with user name begin with "Logan".
    .EXAMPLE
        ./Remove-UserProfile.ps1 -UserName "*" -InactiveDays 30
        Delete all user profiles inactive by 30 days.
    .EXAMPLE
        ./Remove-UserProfile.ps1 -UserName "*" -ExcludeUserName Admistrator
        Delete all user profiles exclude user name Administrator
    .EXAMPLE
        ./Remove-UserProfile.ps1 -UserName "*" -Force
        Delete all user profiles without require confim
    .KUDOS Ermanno Goletto - www.devadmin.it
    .NOTES
        Version:			  0.1
        Creation Date:	05-06-2023
        Author:			    Akos Bakos
        Company:			  SmartCon GmbH
        Contact:			  akos.bakos@smartcon.ch
    
        Copyright (c) 2023 SmartCon GmbH
    
    HISTORY:
    Date			    By			    Comments
    ----------		---			    ----------------------------------------------------------
    05.06.2023    Akos Bakos  Script created
    29.11.2023    Akos Bakos  Clar-RecycleBin command

    #>
    
    [cmdletbinding(ConfirmImpact = 'High', SupportsShouldProcess=`$True)]
    Param(
      [Parameter(Mandatory=`$True)]
      [string]`$UserName,
      [string]`$ExcludeUserName = [string]::Empty,
      [uint32]`$InactiveDays = [uint32]::MaxValue,
      [string[]]`$ComputerName = `$env:computername,
      [switch]`$IncludeSpecialUsers = `$False,
      [switch]`$Force = `$True
    )
    
    `$Global:Transcript = "`$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-RemoveUserProfile.log"
    Start-Transcript -Path (Join-Path "`$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\" `$Global:Transcript) -ErrorAction Ignore | Out-Null
    
    Set-StrictMode -Version latest
    
    ForEach (`$computer in `$ComputerName)
    {
        `$profileFounds = 0
    
      Try {
        `$profiles = Get-WmiObject -Class Win32_UserProfile -Computer `$computer -Filter "Special = '`$IncludeSpecialUsers'" -EnableAllPrivileges
      } Catch {            
        Write-Warning "Failed to retreive user profiles on `$ComputerName"
        Exit
      }
    
      
      ForEach (`$profile in `$profiles) {
        `$sid = New-Object System.Security.Principal.SecurityIdentifier(`$profile.SID)               
        `$account = `$sid.Translate([System.Security.Principal.NTAccount])
        `$accountDomain = `$account.value.split("\")[0]           
        `$accountName = `$account.value.split("\")[1]
        `$profilePath = `$profile.LocalPath
        `$loaded = `$profile.Loaded
        `$lastUseTime = [System.Management.ManagementDateTimeConverter]::ToDateTime(`$profile.LastUseTime)
        `$special = `$profile.Special
    
        #Calculation of the login date
        `$lastLoginDate = `$null
        If (`$accountDomain.ToUpper() -eq `$computer.ToUpper()) {`$lastLoginDate = [datetime]([ADSI]"WinNT://`$computer/`$accountName").LastLogin[0]}
    
        #Calculation of the unused days of the profile
        `$profileUnusedDays=0
        If (-Not `$loaded){
          If(`$lastLoginDate -eq `$null){ `$profileUnusedDays = (New-TimeSpan -Start `$lastUseTime -End (Get-Date)).Days }
          Else{`$profileUnusedDays = (New-TimeSpan -Start `$lastLoginDate -End (Get-Date)).Days} 
        }   
                  
        If(`$accountName.ToLower() -Eq `$UserName.ToLower() -Or 
          (`$UserName.Contains("*") -And `$accountName.ToLower() -Like `$UserName.ToLower())) {
          
          If(`$ExcludeUserName -ne [string]::Empty -And -Not `$ExcludeUserName.Contains("*") -And (`$accountName.ToLower() -eq `$ExcludeUserName.ToLower())){Continue}
          If(`$ExcludeUserName -ne [string]::Empty -And `$ExcludeUserName.Contains("*") -And (`$accountName.ToLower() -Like `$ExcludeUserName.ToLower())){Continue}
    
          If(`$InactiveDays -ne [uint32]::MaxValue -And `$profileUnusedDays -le `$InactiveDays){continue}
    
          `$profileFounds ++
    
          If (`$profileFounds -gt 1) {Write-Host "`n"}
          Write-Host "Start deleting profile ""`$account"" on computer ""`$computer"" ..." -ForegroundColor Green
          Write-Host "Account SID: `$sid"
          Write-Host "Special system service user: `$special"
          Write-Host "Profile Path: `$profilePath"
          Write-Host "Loaded : `$loaded"
          Write-Host "Last use time: `$lastUseTime"
          If (`$lastLoginDate -ne `$null) { Write-Host "Last login: `$lastLoginDate" }
          Write-Host "Profile unused days: `$profileUnusedDays"
    
          If (`$loaded) {
           Write-Warning "Cannot delete profile because is in use"
           Continue
          }
    
          If (`$Force -Or `$PSCmdlet.ShouldProcess(`$account)) {
            Try {
              `$profile.Delete()           
              Write-Host "Profile deleted successfully" -ForegroundColor Green        
            } Catch {            
              Write-Host "Error during delete the profile" -ForegroundColor Red
            }
          } 
        }
      }
    
      If(`$profileFounds -eq 0){
        Write-Warning "No profiles found on `$ComputerName with Name `$UserName"
      }
    }

    Write-Host "Clear all recycle bins without confirmation"
    `$recycleBinPath = Join-Path -Path `$env:SystemDrive -ChildPath '`$Recycle.Bin'
    Remove-Item -Path `$recycleBinPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Stop-Transcript -Verbose | Out-File
"@

    Out-File -FilePath $userConfigScriptPath -InputObject $userConfigScript -Encoding ascii

    $taskName = "Remove User Profile Script v$Version"
    #$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NonInteractive -Executionpolicy Bypass -File $userConfigScriptPath -UserName '*Student*'"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @"
    -WindowStyle Hidden -NonInteractive -Executionpolicy Bypass -File $userConfigScriptPath -UserName "*Student*" -Force
"@
    $trigger = New-ScheduledTaskTrigger -AtStartup

    $class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
    $trigger2 = $class | New-CimInstance -ClientOnly
    $trigger2.Enabled = $True
    $trigger2.Subscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name="Microsoft-Windows-Power-Troubleshooter"] and (EventID=1)]]</Select></Query></QueryList>'

    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -Compatibility Win8
    $task = New-ScheduledTask -Action $action -Trigger $trigger, $trigger2 -Principal $principal -Settings $settings

    Register-ScheduledTask $taskName -InputObject $task -Force | Out-Null

    $taskObject = Get-ScheduledTask -TaskName $taskName
    $taskObject.Author = "Administrator"
    $taskObject | Set-ScheduledTask | Out-Null
}

# Cleanup older scheduled tasks
try {
    $Global:Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Create_RemoveUserProfile_ScheduledTask.log"
    Start-Transcript -Path (Join-Path "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\" $Global:Transcript) -ErrorAction Ignore | Out-Null

    Write-Host "Register a scheduled task to run for all users and execute the script on logon"
    $schtaskName = "Remove User Profile Script v$Version"

    $Target = Get-ScheduledTask | Where-Object { $_.TaskName -eq $schtaskName }                
    If (!$Target) {
        Write-Host "Starting a scheduled task cleanup"

        $Cleanups = Get-ScheduledTask | Where-Object { $_.TaskName -like "Remove User Profile Script v*" }
        foreach ($Cleanup in $Cleanups) {
            Write-Host "Cleaning: $Cleanup.Taskname"
            Unregister-ScheduledTask $Cleanup.TaskName -Confirm:$false
        }

        Write-Host "Create 'Remove User Profile Script v$Version'"
        StartScript
    }

    Else {
        Write-Host "'Remove User Profile Script v$Version' scheduled task already exists"
    }
    Stop-Transcript

    Exit 0
}
catch {
    $errMsg = $_.Exception.Message
    Write-Host $errMsg
    Stop-Transcript

    Exit 1
}
