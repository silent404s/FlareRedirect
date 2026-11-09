@echo off
title FlareRedirect Web Dashboard (Local Engine)
cd /d "%~dp0"
echo ====================================================================
echo   Menjalankan FlareRedirect Web Dashboard di Browser Lokal...
echo ====================================================================
py web/server.py
if errorlevel 1 (
    python web/server.py
)
pause

