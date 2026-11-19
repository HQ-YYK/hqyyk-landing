@echo off
rem keepalive-install.cmd - one-click keepalive installer for the Tianyi cloud PC.
rem Copies keepalive.ps1 to C:\Users\Administrator\, registers the scheduled
rem task and starts it. Keep both files in the same folder. Self-elevating
rem (click Yes on the UAC prompt).
rem NOTE: ASCII only. Tianyi cmd.exe reads UTF-8 Chinese as GBK and mangles lines.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
copy /y "%~dp0keepalive.ps1" "C:\Users\Administrator\keepalive.ps1"
powershell -ExecutionPolicy Bypass -File "C:\Users\Administrator\keepalive.ps1" -Install
echo.
echo Install finished. Press any key to close.
pause >nul
