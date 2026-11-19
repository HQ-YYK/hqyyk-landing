# keepalive.ps1 - Tianyi cloud PC session keepalive.
# ASCII ONLY: Tianyi reads UTF-8-no-BOM scripts as GBK, which garbles Chinese
# and can swallow a $var placed right after a multi-byte char.
# Install in an elevated PowerShell on the Tianyi desktop:
#   powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1 -Install
# Uninstall:
#   powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1 -Uninstall
# Run directly:
#   powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1
# What it does: every 4 minutes nudges the mouse 1px and back, so the platform
# does not reclaim the session for idleness. Install also disables sleep /
# hibernate and registers a scheduled task (auto-start at logon, auto-restart).
# Log: keepalive.log next to this script (start, hourly heartbeat, errors).

param(
  [switch]$Install,
  [switch]$Uninstall
)

$scriptPath = $MyInvocation.MyCommand.Path
$logPath = Join-Path (Split-Path $scriptPath -Parent) "keepalive.log"
$taskName = "Tianyi Keepalive"

function Write-Log($msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $logPath -Value "$ts $msg" -ErrorAction SilentlyContinue
}

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Log "keepalive task removed"
  Write-Output "Keepalive task $taskName removed"
  exit 0
}

if ($Install) {
  powercfg /change standby-timeout-ac 0 | Out-Null
  powercfg /change hibernate-timeout-ac 0 | Out-Null
  powercfg /h off 2>$null | Out-Null
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User "Administrator"
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName $taskName
  Write-Log "keepalive installed, task started"
  Write-Output "Keepalive installed and started, task: $taskName"
  Write-Output "Log: $logPath"
  exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Write-Log "keepalive loop started (pid $PID)"
$tick = 0
while ($true) {
  try {
    $pos = [System.Windows.Forms.Cursor]::Position
    if ($tick -eq 0) { Write-Log "cursor pos type: $($pos.GetType().FullName)" }
    $x = [int]$pos.X
    $y = [int]$pos.Y
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($x + 1), $y)
    Start-Sleep -Milliseconds 200
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)
    $tick++
    if ($tick % 15 -eq 0) { Write-Log "heartbeat ($tick ticks)" }
  } catch {
    Write-Log "tick failed: $($_.Exception.Message)"
  }
  Start-Sleep -Seconds 240
}
