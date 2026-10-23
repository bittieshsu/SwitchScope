@echo off
title SwitchScope - Intelligent Network Device Analyzer
cd /d "%~dp0"

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0launcher.ps1"
if %errorlevel% equ 0 goto end

echo.
echo ===================================================================
echo [Notice] PowerShell execution was blocked or exited.
echo [Notice] Launching SwitchScope Web Server directly in fallback mode...
echo ===================================================================
start "" "http://localhost:8920/"
python server.py
if %errorlevel% neq 0 pause

:end
