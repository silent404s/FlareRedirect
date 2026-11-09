@echo off
title FlareRedirect Web Dashboard (Localhost Engine)
cd /d "%~dp0"
echo ====================================================================
echo   ⚡ Menjalankan FlareRedirect Web Dashboard di http://localhost:5050
echo ====================================================================
py main.py
if errorlevel 1 (
    python main.py
)
pause
