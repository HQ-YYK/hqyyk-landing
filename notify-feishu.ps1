param([string]$Branch = "", [string]$Summary = "")

# ASCII-only on purpose: Tianyi PowerShell 5.1 reads UTF-8-no-BOM files as GBK,
# which garbles Chinese literals (the 2026-11-20 card came out mojibake).
# All fixed Chinese text is built from Unicode codepoints below.
# The webhook URL lives in feishu-webhook.txt next to this script (one line),
# so script updates never touch the secret and switching bots only needs a
# new URL in that file.
function U([int[]]$Codes) { -join ([char[]]$Codes) }

$WebhookFile = Join-Path $PSScriptRoot "feishu-webhook.txt"
if (-not (Test-Path $WebhookFile)) { throw "webhook file missing: $WebhookFile" }
$Webhook = ([System.IO.File]::ReadAllText($WebhookFile, [System.Text.Encoding]::UTF8)).Trim()
if ($Webhook -notmatch "^https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9-]+$") { throw "webhook format invalid" }

$Title = "cloudhub" + (U @(0x9879, 0x76EE))
$Pusher = "OpenClaw" + (U @(0xFF08, 0x5929, 0x7FFC, 0xFF09))
$PushedText = (U @(0x5206, 0x652F, 0x5DF2, 0x63A8, 0x9001, 0xFF0C, 0x5206, 0x652F, 0x540D, 0x662F)) + " " + $Branch
$ByText = (U @(0x63A8, 0x9001, 0x8005)) + (U @(0xFF1A)) + $Pusher + "  " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

$Lines = @($PushedText)
if ($Summary -ne "") { $Lines += $Summary }
$Lines += $ByText
$Content = $Lines -join "`n"

$Card = [ordered]@{
  msg_type = "interactive"
  card = [ordered]@{
    schema = "2.0"
    header = [ordered]@{
      title = [ordered]@{ tag = "plain_text"; content = $Title }
      template = "green"
    }
    body = [ordered]@{
      elements = @(
        [ordered]@{ tag = "markdown"; content = $Content }
      )
    }
  }
}

$Json = $Card | ConvertTo-Json -Depth 10 -Compress
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
Invoke-RestMethod -Uri $Webhook -Method Post -Body $Bytes -ContentType "application/json; charset=utf-8"
