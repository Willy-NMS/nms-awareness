<#
.SYNOPSIS
  NMS Security Awareness - daily content sync (runs as SYSTEM from the scheduled task
  "\NMS\NMS Awareness Sync"). Windows 10/11, PowerShell 5.1.

.DESCRIPTION
  1. Downloads manifest.json from the content site (config.json -> baseUrl).
  2. Keeps the slides for this computer (language, client code, date window).
  3. Downloads new or changed files (logo, images, screensaver, this script), checking SHA-256.
  4. Writes settings.txt and playlist.txt for NMS-Awareness.scr.
  5. Applies the screensaver policy to every signed-in user (HKU\<SID>\Software\Policies\...).
  If the site can't be reached, the slides already on disk keep working.
#>
param([switch]$PolicyOnly, [switch]$NoPolicy)

$ErrorActionPreference = 'Stop'
$Root  = if ($env:NMS_AWARENESS_ROOT) { $env:NMS_AWARENESS_ROOT } else { Join-Path $env:ProgramData 'NMS\Awareness' }
$Cache = Join-Path $Root 'cache'
$Log   = Join-Path $Root 'sync.log'
$Scr   = Join-Path $Root 'NMS-Awareness.scr'

function Write-Log([string]$m) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $m
    try {
        if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 512KB) { Move-Item $Log "$Log.old" -Force }
        Add-Content -Path $Log -Value $line -Encoding UTF8
    } catch { }
    Write-Output $line
}

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant() }

function Save-Url([string]$url, [string]$dest, [string]$sha) {
    $tmp = "$dest.download"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'NMS-Awareness/1.1')
    try { $wc.DownloadFile($url, $tmp) } finally { $wc.Dispose() }
    if ($sha -and (Get-Sha256 $tmp) -ne $sha.ToLowerInvariant()) { Remove-Item $tmp -Force; throw "hash mismatch: $url" }
    Move-Item $tmp $dest -Force
}

function Write-TextAtomic([string]$path, [string[]]$lines) {
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllLines($tmp, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item $tmp $path -Force
}

function Set-UserPolicy($cfg) {
    if (-not (Test-Path $Scr)) { Write-Log 'policy: screensaver file not present yet, skipped'; return }
    $timeout = [string]([int]$cfg.timeoutSec)
    $secure  = if ($cfg.secure -eq $false) { '0' } else { '1' }
    $names = 'ScreenSaveActive', 'ScreenSaverIsSecure', 'ScreenSaveTimeOut', 'SCRNSAVE.EXE'
    $sids = @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-[\d-]+$' } | ForEach-Object { $_.PSChildName })
    if ($sids.Count -eq 0) { Write-Log 'policy: nobody signed in'; return }
    # Values for the live session (read by NMS-Awareness.scr /apply)
    Write-TextAtomic (Join-Path $Root 'session.txt') @("timeoutSec=$timeout", "secure=$secure", "scr=$Scr")

    # 1. Windows reads the policy only at sign-in and refuses live changes while it exists,
    #    so lift it for a few seconds, 2. push the values into the live session, 3. put it back.
    foreach ($sid in $sids) {
        $k = "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        if (Test-Path $k) { foreach ($n in $names) { Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue } }
    }
    Invoke-SessionApply
    foreach ($sid in $sids) {
        $k = "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        New-ItemProperty -Path $k -Name 'ScreenSaveActive'    -Value '1'      -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $k -Name 'ScreenSaverIsSecure' -Value $secure  -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $k -Name 'ScreenSaveTimeOut'   -Value $timeout -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $k -Name 'SCRNSAVE.EXE'        -Value $Scr     -PropertyType String -Force | Out-Null
        # "Prevent changing screen saver": the Screen Saver Settings page can't be opened.
        $s = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        if (-not (Test-Path $s)) { New-Item -Path $s -Force | Out-Null }
        New-ItemProperty -Path $s -Name 'NoDispScrSavPage' -Value 1 -PropertyType DWord -Force | Out-Null
    }
    Write-Log "policy: applied to $($sids.Count) signed-in user(s), timeout ${timeout}s, password on resume=$secure, settings locked"
}

# Task that runs in each signed-in user's session and pushes the policy into the live session
# (Windows otherwise reads it only at sign-in).
function Invoke-SessionApply {
    try {
        $tp = '\NMS\'; $tn = 'NMS Awareness Apply'
        # Task Scheduler can't launch a .scr ("file not found"); use an .exe copy of the same program.
        $App = Join-Path $Root 'NMS-Awareness-Apply.exe'
        if (-not (Test-Path $App) -or (Get-Sha256 $App) -ne (Get-Sha256 $Scr)) { Copy-Item $Scr $App -Force }
        $t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
        if (-not $t -or $t.Actions[0].Execute -ne $App) {
            $users = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')).Translate([System.Security.Principal.NTAccount]).Value
            $action = New-ScheduledTaskAction -Execute $App -Argument '/apply' -WorkingDirectory $Root
            $trig = New-ScheduledTaskTrigger -AtLogOn; $trig.Delay = 'PT1M'
            $pr = New-ScheduledTaskPrincipal -GroupId $users -RunLevel Limited
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskPath $tp -TaskName $tn -Action $action -Trigger $trig -Principal $pr -Settings $set `
                -Description 'NMS Security Awareness: applies the screensaver settings to the signed-in session.' -Force | Out-Null
        }
        $before = (Get-ScheduledTaskInfo -TaskPath $tp -TaskName $tn).LastRunTime
        Start-ScheduledTask -TaskPath $tp -TaskName $tn
        # Wait until this run has started and finished (the policy must stay lifted while it runs).
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 1
            $ran = (Get-ScheduledTaskInfo -TaskPath $tp -TaskName $tn).LastRunTime -ne $before
            if ($ran -and (Get-ScheduledTask -TaskPath $tp -TaskName $tn).State -ne 'Running') { break }
        }
        Start-Sleep -Seconds 1
        $info = Get-ScheduledTaskInfo -TaskPath $tp -TaskName $tn
        Write-Log "session apply: result $($info.LastTaskResult)"
    } catch { Write-Log "session apply failed: $($_.Exception.Message)" }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $cfg = Get-Content (Join-Path $Root 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($PolicyOnly) { Set-UserPolicy $cfg; exit 0 }
    New-Item -ItemType Directory -Force $Cache | Out-Null

    $base = $cfg.baseUrl.TrimEnd('/') + '/'
    $lang = if ($cfg.lang) { $cfg.lang } else { 'en' }
    $client = [string]$cfg.client
    $today = (Get-Date).ToString('yyyy-MM-dd')

    $mfPath = Join-Path $Root 'manifest.json'
    try {
        $bust = if ($base -like 'http*') { '?t=' + [DateTime]::UtcNow.Ticks } else { '' }
        Save-Url ($base + 'manifest.json' + $bust) $mfPath $null
    } catch {
        Write-Log "manifest download failed ($($_.Exception.Message)); using the copy on disk"
        if (-not (Test-Path $mfPath)) { throw 'no manifest on disk yet' }
    }
    $m = Get-Content $mfPath -Raw -Encoding UTF8 | ConvertFrom-Json

    # Language: the central list in the manifest (by NinjaOne organization) wins over the install value.
    $map = $m.settings.languages
    if ($map -and $client) {
        $hit = $map.PSObject.Properties | Where-Object { $_.Name -eq $client } | Select-Object -First 1
        if ($hit) { $lang = [string]$hit.Value }
        elseif ($map.'*') { $lang = [string]$map.'*' }
    }

    $keep = @{}
    # Logo
    $logoName = ''
    if ($m.logo) {
        $logoName = Split-Path $m.logo.file -Leaf
        $dest = Join-Path $Cache $logoName
        if (-not (Test-Path $dest) -or (Get-Sha256 $dest) -ne $m.logo.sha256) { Save-Url ($base + $m.logo.file) $dest $m.logo.sha256; Write-Log "logo updated" }
        $keep[$logoName] = $true
    }

    # Screensaver binary
    if ($m.screensaver) {
        if (-not (Test-Path $Scr) -or (Get-Sha256 $Scr) -ne $m.screensaver.sha256) {
            try { Save-Url ($base + $m.screensaver.file) $Scr $m.screensaver.sha256; Write-Log "screensaver updated to $($m.screensaver.version)" }
            catch { Write-Log "screensaver update postponed: $($_.Exception.Message)" }
        }
    }

    # This script (takes effect on the next run)
    if ($m.agent) {
        $self = Join-Path $Root 'Sync-NmsAwareness.ps1'
        if ((Test-Path $self) -and (Get-Sha256 $self) -ne $m.agent.sha256) {
            try { Save-Url ($base + $m.agent.file) $self $m.agent.sha256; Write-Log 'sync script updated' } catch { Write-Log "sync script update failed: $($_.Exception.Message)" }
        }
    }

    # Slides for this computer
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($m.slides)) {
        if ($s.lang -and $s.lang -ne $lang) { continue }
        $cl = @($s.clients)
        if ($cl.Count -gt 0 -and -not ($cl -contains '*' -or ($client -and $cl -contains $client))) { continue }
        if (@($s.exclude) -contains $client) { continue }
        if ($s.from -and $today -lt $s.from) { continue }
        if ($s.to -and $today -gt $s.to) { continue }
        $img = ''
        if ($s.image -and $s.image.file) {
            $img = Split-Path $s.image.file -Leaf
            $dest = Join-Path $Cache $img
            try {
                if (-not (Test-Path $dest) -or (Get-Sha256 $dest) -ne $s.image.sha256) { Save-Url ($base + $s.image.file) $dest $s.image.sha256 }
                $keep[$img] = $true
            } catch { Write-Log "image skipped ($img): $($_.Exception.Message)"; continue }
        }
        $clean = { param($t) ([string]$t) -replace "[`t`r`n]", ' ' }
        $fields = @((& $clean $s.id), (& $clean $s.title), ((@($s.bullets) | ForEach-Object { & $clean $_ }) -join '|'),
            (& $clean $s.art), (& $clean $s.url), $img, ((@($s.artText) | ForEach-Object { & $clean $_ }) -join '|'))
        $lines.Add($fields -join "`t")
    }

    $st = $m.settings
    $lab = $st.labels.$lang
    if (-not $lab) { $lab = $st.labels.en }
    Write-TextAtomic (Join-Path $Root 'settings.txt') @(
        "slideSeconds=$($st.slideSeconds)", "company=$($st.company)", "phone=$($st.phone)", "website=$($st.website)",
        "callLabel=$($lab.call)", "scanLabel=$($lab.scan)", "defaultUrl=$($st.defaultUrl)", "logo=$logoName", "manifest=$($m.version)")
    Write-TextAtomic (Join-Path $Root 'playlist.txt') $lines.ToArray()

    # Remove files that are no longer used
    Get-ChildItem $Cache -File | Where-Object { -not $keep.ContainsKey($_.Name) } | Remove-Item -Force -ErrorAction SilentlyContinue

    Write-Log "content $($m.version): $($lines.Count) slide(s) for lang=$lang client=$client"
    if (-not $NoPolicy) { Set-UserPolicy $cfg }
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
