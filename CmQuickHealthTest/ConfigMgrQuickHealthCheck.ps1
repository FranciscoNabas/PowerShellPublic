<#
    .SYNOPSIS
        The Configuration Manager Quick Health Check verifies if the client installed on the machine is healthy.

    .DESCRIPTION
        This solution is based on the documentation for Client Health Check from Microsoft.
        It performs the following tests:

            - Check services.
            - Check CcmEval task.
            - Check client database.
            - Check WMI.
            - Check Policy Platform.
    
    .NOTES
        This script needs to run with administrator priviledges.

        Copyright (c) 2022 Francisco Nabas
        This software is licenced under the GNU GPLv3
        https://github.com/FranciscoNabas

    .LINK
        https://learn.microsoft.com/en-us/mem/configmgr/core/clients/manage/client-health-checks
#>

#requires -RunAsAdministrator

[CmdletBinding()]
param (

    ## Does not create the cleanup task
    [Parameter()]
    [switch]$Test
    
)

#region Functions
function Invoke-FinalWarning {

    param(
        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [ValidateSet('Healthy', 'Not Healthy')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Action
    )

    Write-Host @"

############################################################
#                                                          #
#          ~ Config. Manager Client Health Test ~          #
#                                                          #
# End of execution: $((Get-Date -Format 'dd/MM/yyy hh:mm:ss').ToString().PadRight(39, ' '))#
#                                                          #
# Client Status: $($Status.PadRight(42, ' '))#
# Reason: $($Reason.PadRight(49, ' '))#
# Action: $($Action.PadRight(49, ' '))#
#                                                          #
############################################################

"@ -ForegroundColor DarkGreen

}

function Start-ServiceWithRetryAndWait {

    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $svchandle = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svchandle.Status -ne 'Running') {
        $attempts = 0
        try {
            Write-Verbose "'$Name' service is not running. Attempting to start."
            do {
                Start-Service $service -ErrorAction Stop
                Start-Sleep -Seconds 15
                $svchandle = Get-Service -Name $service -ErrorAction Stop
                $attempts++
            } while (($svchandle.Status -ne 'Running') -or ($attempts -lt 3))

            if ($svchandle.Status -ne 'Running') {
                Write-Warning "Failed starting service '$Name'."
                return $false
            }
        }
        catch {
            Write-Warning "Failed starting service '$Name'. $($PSItem.Exception.Message)"
            return $false
        }
    }

    return $true
}

function Get-ServiceStartTypeWithSet {

    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Automatic', 'AutomaticDelayedStart', 'Manual', 'Disabled')]
        [string]$StartType
    )

    $svchandle = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svchandle.StartType -ne $StartType) {
        Write-Verbose "'$Name' service startup type is not $StartType. Remediating.'"
        try {
            Set-Service -InputObject $svchandle -StartupType $StartType -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed changing service '$Name' startup type to $StartType. $($PSItem.Exception.Message)"
            return $false
        }
    }

    return $true

}

function Invoke-EndOfExecution {

    param($errorcode)

    Read-Host -Prompt 'Execution terminated. Press any key to exit...'
    exit $errorcode

}

function Set-CleanupTask {

    $sb = @"
do {
    Remove-Item '$PSScriptRoot' -Recurse -Force -ErrorAction SilentlyContinue
    Sleep 1
}
while (Test-Path -Path '$PSScriptRoot')
    
Unregister-ScheduledTask -TaskName 'CmQuickHealthCheckCleanup' -Confirm:`$false -ErrorAction SilentlyContinue
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($sb)
    $encoded = [convert]::ToBase64String($bytes)

    Unregister-ScheduledTask -TaskName 'CmQuickHealthCheckCleanup' -Confirm:$false -ErrorAction SilentlyContinue
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $root = $scheduler.GetFolder('\')

    $definition = $scheduler.NewTask(0)
    $definition.Principal.UserId = 'NT AUTHORITY\SYSTEM'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1
    
    $trigger = $definition.Triggers.Create(1)
    $trigger.StartBoundary = (Get-Date -Date ([datetime]::Now.AddMinutes(10)) -Format 'yyyy-MM-ddThh:mm:ss').ToString()

    $action = $definition.Actions.Create(0)
    $action.Path = 'powershell.exe'
    $action.Arguments = "-ExecutionPolicy Bypass -EncodedCommand $encoded"

    [void]$root.RegisterTaskDefinition('CmQuickHealthCheckCleanup', $definition, 6, '', '', 5)

}
#endregion

$pcsystem = Get-CimInstance -ClassName Win32_ComputerSystem
Write-Host @"
############################################################
#                                                          #
#          ~ Config. Manager Client Health Test ~          #
#                                                          #
# Starting execution: $((Get-Date -Format 'dd/MM/yyy hh:mm:ss').ToString().PadRight(37, ' '))#
#                                                          #
# Computer name: $($env:COMPUTERNAME.PadRight(42, ' '))#
# Primary user: $($pcsystem.UserName.PadRight(43, ' '))#
# Domain: $($pcsystem.Domain.PadRight(49, ' '))#
#                                                          #
############################################################

"@ -ForegroundColor DarkGreen

Write-Host "Creating cleanup task" -ForegroundColor DarkCyan
if (!$Test) { Set-CleanupTask }

#region Services
Write-Host "Checking services" -ForegroundColor Gray
$services = @(
    'CcmExec'
    'ccmsetup'
    'wuauserv'
    'BITS'
    'Winmgmt'
    'lppsvc'
)

foreach ($service in $services) {
    $svchandle = $null
    switch ($service) {
        'CcmExec' {
            $svchandle = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (!$svchandle) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "'CcmExec' service not found" -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Get-ServiceStartTypeWithSet -Name $service -StartType 'Automatic')) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed to change '$service' service startup type" -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Start-ServiceWithRetryAndWait -Name $service)) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed to start service '$service'" -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }
        }
        'ccmsetup' {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason 'Ccmsetup service exists' -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }
        }
        'wuauserv' {
            $svchandle = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (!$svchandle) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason 'Windows Update service not found' -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Get-ServiceStartTypeWithSet -Name $service -StartType 'Automatic')) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed changing 'wuauserv' service startup type to Automatic" -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }
        }

        'BITS' {
            $svchandle = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (!$svchandle) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "'BITS' service not found'" -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }

            if (($svchandle.StartType -ne 'Automatic') -and ($svchandle.StartType -ne 'Manual')) {
                Write-Verbose "'$service' service startup type is not Automatic or Manual. Remediating.'"
                try {
                    Set-Service -InputObject $svchandle -StartupType Automatic -ErrorAction Stop
                }
                catch {
                    Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                    Write-Host "fail" -ForegroundColor Red
                    Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed changing 'BITS' service startup type to Automatic" -Action 'Reinstall Windows OS'
                    Invoke-EndOfExecution -errorcode 0
                }
            }
        }

        'Winmgmt' {
            $svchandle = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (!$svchandle) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "WMI service not found" -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Get-ServiceStartTypeWithSet -Name $service -StartType 'Automatic')) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed to change WMI service startup type" -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Start-ServiceWithRetryAndWait -Name $service)) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed to start WMI service" -Action 'Reinstall Windows OS'
                Invoke-EndOfExecution -errorcode 0
            }
        }

        'lppsvc' {
            $svchandle = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (!$svchandle) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "'$service' service not found" -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }

            if (!(Get-ServiceStartTypeWithSet -Name $service -StartType 'Manual')) {
                Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
                Write-Host "fail" -ForegroundColor Red
                Invoke-FinalWarning -Status 'Not Healthy' -Reason "Failed to change '$service' service startup type" -Action 'Reinstall the client'
                Invoke-EndOfExecution -errorcode 0
            }
        }
    }

    Write-Host "    Service '$service': " -ForegroundColor DarkCyan -NoNewline
    Write-Host "pass" -ForegroundColor Green
}
Write-Host ' '
#endregion

#region CcmEvalTask
Write-Host "Client evaluation task" -ForegroundColor Gray
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$folder = $scheduler.GetFolder('\Microsoft\Configuration Manager')

try {
    $task = $folder.GetTask('Configuration Manager Health Evaluation')    
}
catch {
    if ($PSItem.Exception.Message -match '(0x80070002)') {
        Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
        Write-Host "fail" -ForegroundColor Red
        Invoke-FinalWarning -Status 'Not Healthy' -Reason 'CcmEval task not found' -Action 'Reinstall the client'
        exit 0
    }
}

if (([datetime]::Now - ($task.LastRunTime)).TotalDays -gt 3) {
    Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
    Write-Host "fail" -ForegroundColor Red
    Write-Host "    CcmEval task didn't ran in the past 3 days. If the client was not installed recently, reinstall it." -ForegroundColor DarkYellow
}
else {
    Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
    Write-Host "pass" -ForegroundColor Green
    Write-Host ' '
}

while ($refcount -gt 0) { $refcount = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($scheduler) }
#endregion

#region SQLCE
Write-Host 'Client Database' -ForegroundColor Gray
try {
    Stop-Service -Name 'CcmExec' -Force -ErrorAction Stop -WarningAction SilentlyContinue
    $databases = @(
        'CcmStore.sdf'
        'StateMessageStore.sdf'
        'InventoryStore.sdf'
        'UserAffinityStore.sdf'
        'CertEnrollmentStore.sdf'
    )

    if (!([System.AppDomain]::CurrentDomain.GetAssemblies().Location -contains "$PSScriptRoot\Lib\System.Data.SqlServerCe.dll")) {
        [void][System.Reflection.Assembly]::UnsafeLoadFrom("$PSScriptRoot\Lib\System.Data.SqlServerCe.dll")
    }

    $engine = New-Object 'System.Data.SqlServerCe.SqlCeEngine'

    foreach ($database in $databases) {
        $engine.LocalConnectionString = "Data Source = C:\Windows\CCM\$database"
        if (!$engine.Verify([System.Data.SqlServerCe.VerifyOption]::Default)) {
            Start-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
            Write-Host "    $($database): " -ForegroundColor DarkCyan -NoNewline
            Write-Host "fail" -ForegroundColor Red
            Invoke-FinalWarning -Status 'Not Healthy' -Reason "Client database corrupted" -Action 'Reinstall the client'
            Invoke-EndOfExecution -errorcode 0
        }
        Write-Host "    $($database): " -ForegroundColor DarkCyan -NoNewline
        Write-Host "pass" -ForegroundColor Green
    }

    Start-Service -Name 'CcmExec' -ErrorAction Stop
    $engine.Dispose()
    Write-Host ' '
}
catch {
    Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
    Write-Host "fail" -ForegroundColor Red
    Write-Host "    $($PSItem.Exception.Message)" -ForegroundColor DarkYellow
    Invoke-FinalWarning -Status 'Not Healthy' -Reason "Client database corrupted" -Action 'Reinstall the client'
    Invoke-EndOfExecution -errorcode 0
}
#endregion

#region WmiRepo
Write-Host 'WMI Repository' -ForegroundColor Gray
if ((WinMgmt.exe /verifyrepository) -ne 'WMI repository is consistent') {
    Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
    Write-Host "fail" -ForegroundColor Red
    Write-Host "    Attempting to salvage..." -ForegroundColor DarkYellow
    [void](WinMgmt.exe /salvagerepository)
    
    if ((WinMgmt.exe /verifyrepository) -ne 'WMI repository is consistent') {
        Write-Host "        Status: " -ForegroundColor DarkCyan -NoNewline
        Write-Host "fail" -ForegroundColor Red
        Invoke-FinalWarning -Status 'Not Healthy' -Reason "Inconsistent WMI repository" -Action 'Reinstall Windows OS'
        Invoke-EndOfExecution -errorcode 0
    }
}
Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
Write-Host "pass" -ForegroundColor Green
Write-Host ' '
#endregion

#region PolicyPlatform
Write-Host 'Policy Platform' -ForegroundColor Gray
if (!(Get-CimInstance -Namespace 'root/Microsoft' -Query "Select * From __NAMESPACE Where Name = 'PolicyPlatform'")) {
    Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
    Write-Host "fail" -ForegroundColor Red
    Invoke-FinalWarning -Status 'Not Healthy' -Reason "Policy Platform namespace not found" -Action 'Reinstall the client'
    Invoke-EndOfExecution -errorcode 0
}
Write-Host "    Status: " -ForegroundColor DarkCyan -NoNewline
Write-Host "pass" -ForegroundColor Green
#endregion

Invoke-FinalWarning -Status 'Healthy' -Reason 'Passed all checks' -Action ' '
Invoke-EndOfExecution -errorcode 0