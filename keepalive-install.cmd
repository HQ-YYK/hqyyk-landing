@echo off
rem keepalive-install.cmd — 天翼云电脑保活一键安装（双击运行）
rem 作用：把 keepalive.ps1 拷到 C:\Users\Administrator\，注册计划任务并启动。
rem 需要和 keepalive.ps1 放在同一文件夹。会自动提权（弹 UAC 时点“是”即可）。
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
copy /y "%~dp0keepalive.ps1" "C:\Users\Administrator\keepalive.ps1"
powershell -ExecutionPolicy Bypass -File "C:\Users\Administrator\keepalive.ps1" -Install
echo.
echo 安装完成，按任意键关闭。
pause >nul
