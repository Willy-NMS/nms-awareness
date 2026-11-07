<#
.SYNOPSIS
  Removes the NMS Security Awareness screensaver. Run from NinjaOne as SYSTEM.
  Deletes the scheduled task, the screensaver policy from every user profile
  (signed in or not) and C:\ProgramData\NMS\Awareness.
#>
$ErrorActionPreference = 'Continue'
$Root = Join-Path $env:ProgramData 'NMS\Awareness'
$rel = 'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
$names = 'ScreenSaveActive', 'ScreenSaverIsSecure', 'ScreenSaveTimeOut', 'SCRNSAVE.EXE'

foreach ($tn in 'NMS Awareness Sync', 'NMS Awareness Apply', 'NMS Awareness Unlock') { Unregister-ScheduledTask -TaskName $tn -TaskPath '\NMS\' -Confirm:$false -ErrorAction SilentlyContinue }
Get-Process -Name 'NMS-Awareness*' -ErrorAction SilentlyContinue | Stop-Process -Force

function Clear-Policy([string]$hiveRoot) {
    $k = "Registry::$hiveRoot\$rel"
    if (Test-Path $k) {
        $p = Get-ItemProperty $k
        # Only remove values that point to our screensaver (leave a client's own GPO alone)
        if ($p.'SCRNSAVE.EXE' -like '*NMS\Awareness*') {
            foreach ($n in $names) { Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue }
            Remove-ItemProperty -Path "Registry::$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'NoDispScrSavPage' -ErrorAction SilentlyContinue
            return $true }
    }
    return $false
}

$done = 0
$loaded = Get-ChildItem Registry::HKEY_USERS | ForEach-Object { $_.PSChildName }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
    $sid = $_.PSChildName
    if ($sid -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { return }
    if ($loaded -contains $sid) { if (Clear-Policy "HKEY_USERS\$sid") { $done++ }; return }
    $dat = Join-Path $_.GetValue('ProfileImagePath') 'NTUSER.DAT'
    if (-not (Test-Path $dat)) { return }
    & reg.exe load "HKU\NMSAW_$sid" "$dat" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        if (Clear-Policy "HKEY_USERS\NMSAW_$sid") { $done++ }
        [gc]::Collect(); Start-Sleep -Milliseconds 300
        & reg.exe unload "HKU\NMSAW_$sid" 2>$null | Out-Null
    }
}
Remove-Item $Root -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "NMS Awareness removed. Policy cleared in $done profile(s)."
exit 0
