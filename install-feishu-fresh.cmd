@echo off
copy /Y "%~dp0notify-feishu.ps1" "C:\Users\Administrator\notify-feishu.ps1" > "%~dp0feishu-fresh-result.txt" 2>&1
dir "C:\Users\Administrator\notify-feishu.ps1" >> "%~dp0feishu-fresh-result.txt" 2>&1
