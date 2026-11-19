# keepalive.ps1 — 天翼云电脑会话保活
# 保存到 C:\Users\Administrator\keepalive.ps1，在桌面 PowerShell（管理员）里跑：
#   安装：  powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1 -Install
#   卸载：  powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1 -Uninstall
#   直接跑：powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\keepalive.ps1
# 作用：每 4 分钟把鼠标轻移 1 像素再移回来，防止会话因空闲被平台回收；
#       安装时顺带关掉睡眠/休眠，并注册计划任务（登录自启，失败自动重启）。
# 日志：同目录下的 keepalive.log（启动、心跳每小时一条、报错都记）。

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
  Write-Output "已卸载保活任务 $taskName"
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
  Write-Output "保活已安装并启动，任务名：$taskName"
  Write-Output "日志：$logPath"
  exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Write-Log "keepalive loop started (pid $PID)"
$tick = 0
while ($true) {
  try {
    $pos = [System.Windows.Forms.Cursor]::Position
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($pos.X + 1, $pos.Y)
    Start-Sleep -Milliseconds 200
    [System.Windows.Forms.Cursor]::Position = $pos
    $tick++
    if ($tick % 15 -eq 0) { Write-Log "heartbeat ($tick ticks)" }
  } catch {
    Write-Log "tick failed: $($_.Exception.Message)"
  }
  Start-Sleep -Seconds 240
}
