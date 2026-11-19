@echo off
for %%f in ("%~dp0install-feishu*.ps1") do powershell -ExecutionPolicy Bypass -File "%%f"
