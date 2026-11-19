@echo off
rem magpie-test.cmd - runs magpie-test*.ps1 (read-only diagnostic).
rem Writes magpie-test-result.txt next to the script. Makes no changes.
rem No elevation needed. ASCII only.
for %%f in ("%~dp0magpie-test*.ps1") do powershell -ExecutionPolicy Bypass -File "%%f"
