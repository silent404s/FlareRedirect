@echo off
title FlareRedirect Web Dashboard (Local Engine)
cd /d "%~dp0"
echo ====================================================================
echo   Menjalankan FlareRedirect Web Dashboard di Browser Lokal...
echo ====================================================================
py server.py
if errorlevel 1 (
    python server.py
)
pause

