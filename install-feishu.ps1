# Install the rewritten notify-feishu.ps1 on Tianyi.
# The webhook URL never leaves this machine: it is read from the old script
# and injected into the new one (which carries only a placeholder).
$AdminDir = "C:\Users\Administrator"
$Old = Join-Path $AdminDir "notify-feishu.ps1"
$Result = Join-Path $PSScriptRoot "feishu-install-result.txt"
$Log = @()
$Log += "date: " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
try {
  $NewFile = Get-ChildItem "$PSScriptRoot\notify-feishu*.ps1" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $NewFile) { throw "new notify-feishu.ps1 not found in $PSScriptRoot" }
  $Log += "new file: $($NewFile.Name), $($NewFile.Length) bytes"
  $OldText = [System.IO.File]::ReadAllText($Old, [System.Text.Encoding]::UTF8)
  $M = [regex]::Match($OldText, "https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9-]+")
  if (-not $M.Success) { throw "webhook not found in old script" }
  $Hook = $M.Value
  $Log += "webhook found: yes, length $($Hook.Length)"
  $NewText = [System.IO.File]::ReadAllText($NewFile.FullName, [System.Text.Encoding]::UTF8)
  if ($NewText -notmatch "__FEISHU_WEBHOOK__") { throw "placeholder missing in new script" }
  $NewText = $NewText.Replace("__FEISHU_WEBHOOK__", $Hook)
  [System.IO.File]::WriteAllText($Old, $NewText, [System.Text.Encoding]::UTF8)
  $Log += "installed: yes, $($NewText.Length) chars"
  $Resp = & $Old -Branch "test" -Summary "encoding fix test"
  $Log += "test code: $($Resp.code), msg: $($Resp.msg)"
} catch {
  $Log += "ERROR: $($_.Exception.Message)"
}
$Log | Out-File $Result -Encoding ascii
try { Copy-Item $Result (Join-Path $AdminDir "feishu-install-result.txt") -Force } catch { }
