@echo off
title FlareRedirect v1.1.0
echo Menjalankan FlareRedirect...
py main.py
if errorlevel 1 (
    python main.py
)
if errorlevel 1 (
    "%LOCALAPPDATA%\Python\bin\python.exe" main.py
)
pause
