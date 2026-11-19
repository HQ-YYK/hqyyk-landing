# magpie-test.ps1 - READ-ONLY diagnostic for Tianyi -> local magpie.
# Writes results next to this script (magpie-test-result.txt) and also to
# C:\Users\Administrator\magpie-test-result.txt. Makes no changes.
# Never logs the key value, only its length. ASCII only (Tianyi reads
# UTF-8-no-BOM scripts as GBK).
$out = Join-Path $PSScriptRoot "magpie-test-result.txt"
$lines = @()
$lines += "date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$lines += "--- env key ---"
$key = ""
$line = Get-Content C:\Users\Administrator\.openclaw\.env -ErrorAction SilentlyContinue | Where-Object { $_ -match '^MAGPIE_KEY=' } | Select-Object -First 1
if ($line) {
  $key = $line.Split('=', 2)[1].Trim().Trim('"')
  $lines += "key found: yes, length $($key.Length)"
} else {
  $lines += "key found: NO"
}
$lines += "--- no-key curl ---"
$body1 = curl.exe -s -m 15 http://100.69.38.125:3425/v1/models 2>&1 | Out-String
$lines += "exit: $LASTEXITCODE"
$lines += "body: $body1"
$lines += "--- with-key curl ---"
$body2 = ""
if ($key -ne "") {
  $body2 = curl.exe -s -m 15 -H "Authorization: Bearer $key" http://100.69.38.125:3425/v1/models 2>&1 | Out-String
  $lines += "exit: $LASTEXITCODE"
  $lines += "body: $body2"
} else {
  $lines += "skipped (no key)"
}
$lines += "--- model ids ---"
if ($body2) {
  try {
    $ids = ($body2 | ConvertFrom-Json).data.id
    if ($ids) { foreach ($id in $ids) { $lines += "model: $id" } } else { $lines += "no ids parsed" }
  } catch {
    $lines += "parse failed: $($_.Exception.Message)"
  }
} else {
  $lines += "skipped (no body)"
}
$lines += "--- tailscale status ---"
if (Get-Command tailscale -ErrorAction SilentlyContinue) {
  $lines += (tailscale status 2>&1 | Out-String)
} else {
  $lines += "tailscale not on PATH"
}
$lines += "--- openclaw models list ---"
if (Get-Command openclaw -ErrorAction SilentlyContinue) {
  $lines += (openclaw models list 2>&1 | Out-String)
} else {
  $lines += "openclaw not on PATH"
}
$lines | Set-Content $out -Encoding Ascii
Copy-Item $out C:\Users\Administrator\magpie-test-result.txt -Force -ErrorAction SilentlyContinue
