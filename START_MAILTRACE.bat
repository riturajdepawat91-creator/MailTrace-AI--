@echo off

cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0START_MAILTRACE.ps1"

pause
