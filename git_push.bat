@echo off
title Push FlareRedirect to GitHub
echo ====================================================================
echo     PUSH FLAREREDIRECT REPOSITORY TO GITHUB
echo ====================================================================
echo Remote: https://github.com/silent404s/FlareRedirect
echo Branch: main
echo.
git push -u origin main
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [INFO] Jika prompt autentikasi muncul, silakan login dengan akun GitHub Anda.
) else (
    echo.
    echo [SUKSES] Repository berhasil di-push ke https://github.com/silent404s/FlareRedirect!
)
echo.
pause

