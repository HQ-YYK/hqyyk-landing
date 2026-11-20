@echo off
copy /Y "C:\Users\Administrator\feishu-webhook-chicken.bak" "C:\Users\Administrator\feishu-webhook.txt" > "%~dp0webhook-restore-result.txt" 2>&1
