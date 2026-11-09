<#
.SYNOPSIS
  Installs the NMS Security Awareness screensaver. Run from NinjaOne as SYSTEM.

.DESCRIPTION
  - C:\ProgramData\NMS\Awareness (SYSTEM/Admins full, Users read only)
  - config.json with the content site, client code, language and timeout
  - downloads Sync-NmsAwareness.ps1 from the content site (hash checked) and runs it
  - scheduled task "\NMS\NMS Awareness Sync" as SYSTEM: at startup, at every sign-in and every hour
  The screensaver starts after the timeout and asks for the Windows password when the user comes back.

  NinjaOne: parameters can be passed as script arguments or as script variables
  (environment variables): client, language, timeoutMinutes, requirePassword, baseUrl.
  client defaults to the NinjaOne organization name. The language for each organization is set centrally
  in slides.json (settings.languages) and applied on every daily sync. Servers are skipped.

.EXAMPLE
  Install-NmsAwareness.ps1 -Client ACE -Language es
#>
param(
    [string]$Client = $env:client,
    [string]$Language = $env:language,
    [int]$TimeoutMinutes = 0,
    [string]$RequirePassword = $env:requirePassword,
    [string]$BaseUrl = $env:baseUrl
)
$ErrorActionPreference = 'Stop'
if (-not $BaseUrl) { $BaseUrl = 'https://willy-nms.github.io/nms-awareness/' }
if (-not $Language) { $Language = 'en' }
if ($TimeoutMinutes -le 0) { $TimeoutMinutes = if ($env:timeoutMinutes) { [int]$env:timeoutMinutes } else { 20 } }
$secure = -not ($RequirePassword -match '^(0|false|no)$')
$Language = $Language.ToLowerInvariant()
if (-not $Client) { $Client = $env:NINJA_ORGANIZATION_NAME }   # NinjaOne sets this for every script
$Client = ([string]$Client).Trim()
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1 -and -not $env:allowServers) { Write-Output "Skipped: $($os.Caption) is a server."; exit 0 }

$Root = Join-Path $env:ProgramData 'NMS\Awareness'
New-Item -ItemType Directory -Force (Join-Path $Root 'cache') | Out-Null
# Only SYSTEM and Administrators can change the files; users can read and run them.
# Take ownership first and reset the files to inherit from the folder (a file left with its own ACL
# from an earlier install would otherwise block the update with "Access denied").
& takeown.exe /F $Root /R /A /D Y 2>&1 | Out-Null
& icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /C /Q | Out-Null
& icacls.exe "$Root\*" /reset /T /C /Q 2>&1 | Out-Null
Get-ChildItem $Root -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.IsReadOnly } | ForEach-Object { $_.IsReadOnly = $false }

$cfg = [ordered]@{
    baseUrl = $BaseUrl; client = $Client; lang = $Language
    timeoutSec = $TimeoutMinutes * 60; secure = $secure; installed = (Get-Date).ToString('s')
}
[System.IO.File]::WriteAllText((Join-Path $Root 'config.json'), ($cfg | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$m = $wc.DownloadString($BaseUrl.TrimEnd('/') + '/manifest.json?t=' + [DateTime]::UtcNow.Ticks) | ConvertFrom-Json
$sync = Join-Path $Root 'Sync-NmsAwareness.ps1'
$wc.DownloadFile($BaseUrl.TrimEnd('/') + '/' + $m.agent.file, "$sync.download")
$wc.Dispose()
if ((Get-FileHash "$sync.download" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.agent.sha256) { Remove-Item "$sync.download" -Force; throw 'Sync script hash mismatch' }
Move-Item "$sync.download" $sync -Force

# Scheduled task (SYSTEM): startup, every sign-in (applies the policy to that user) and daily.
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$sync`""
$t1 = New-ScheduledTaskTrigger -AtStartup; $t1.Delay = 'PT2M'
$t2 = New-ScheduledTaskTrigger -AtLogOn;   $t2.Delay = 'PT30S'
$t3 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes((Get-Random -Maximum 59)) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)   # hourly: re-enforces the settings
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'NMS Awareness Sync' -TaskPath '\NMS\' -Action $action -Trigger $t1, $t2, $t3 -Principal $principal -Settings $settings `
    -Description 'NMS Security Awareness: downloads the screensaver slides and applies the screensaver policy.' -Force | Out-Null

& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $sync
$rc = $LASTEXITCODE
Write-Output "NMS Awareness installed: client=$Client lang=$Language timeout=${TimeoutMinutes}min password=$secure sync=$rc"
Write-Output 'Signed-in users get it now; the timeout change is fully applied at their next sign-in or lock.'
exit $rc
