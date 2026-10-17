@echo off
powershell.exe -NoProfile -File "%~dp0serve.ps1"
if errorlevel 1 pause
