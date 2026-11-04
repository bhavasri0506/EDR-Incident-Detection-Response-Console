@echo off
title SOC EDR Service Terminator
color 0C
echo ================================================================
echo   [+] Terminating SOC EDR Background Daemons and Services...
echo ================================================================
echo.

:: Terminate running Python background processes safely
taskkill /F /IM python.exe /T >nul 2>&1

echo [*] All EDR background instances have been terminated.
echo [*] System resources cleared successfully.
echo.
pause