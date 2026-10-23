@echo off
chcp 65001 >nul
title SwitchScope - Intelligent Network Device Analyzer
cd /d "%~dp0"

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0launcher.ps1"
if %errorlevel% neq 0 (
    echo.
    echo ===================================================================
    echo [提示] 若 PowerShell 執行受阻，正在自動切換為直接啟動模式...
    echo ===================================================================
    start "" "http://localhost:8920/"
    python server.py
    if %errorlevel% neq 0 pause
)
