@echo off
powershell -ExecutionPolicy Bypass -File "C:\Users\Administrator\notify-feishu.ps1" -Branch "test" -Summary "monkey bot test" > "%~dp0feishu-test-result.txt" 2>&1
copy /Y "%~dp0feishu-test-result.txt" "C:\Users\Administrator\feishu-test-result.txt" >nul 2>&1
