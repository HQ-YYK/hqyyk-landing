# Install the rewritten notify-feishu.ps1 on Tianyi.
# The webhook URL never leaves this machine: it is read from the old script
# and saved to feishu-webhook.txt, which the new script reads at runtime.
$AdminDir = "C:\Users\Administrator"
$Old = Join-Path $AdminDir "notify-feishu.ps1"
$WebhookFile = Join-Path $AdminDir "feishu-webhook.txt"
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
  [System.IO.File]::WriteAllText($WebhookFile, $Hook, [System.Text.Encoding]::ASCII)
  $Log += "webhook file written: yes"
  Copy-Item $NewFile.FullName $Old -Force
  $Log += "installed: yes"
  $Resp = & $Old -Branch "test" -Summary "encoding fix test"
  $Log += "test code: $($Resp.code), msg: $($Resp.msg)"
} catch {
  $Log += "ERROR: $($_.Exception.Message)"
}
$Log | Out-File $Result -Encoding ascii
try { Copy-Item $Result (Join-Path $AdminDir "feishu-install-result.txt") -Force } catch { }
