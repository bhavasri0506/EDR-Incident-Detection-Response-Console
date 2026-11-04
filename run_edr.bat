@echo off
title SOC EDR Auto Launcher
color 0B
echo ================================================================
echo   [+] SOC EDR Operations Environment Launcher
echo   [+] Initializing Background Daemons and Services...
echo ================================================================
echo.

:: Switch working directory to current script path
cd /d "%~dp0"

:: 1. Launch Backend Telemetry Server
echo [*] Initializing Backend Telemetry Ingestion Server...
start "EDR Backend Server" /min cmd /k "python server/server.py"

:: Wait 3 seconds for port 5000 to bind
timeout /t 3 /nobreak >nul

:: 2. Launch Endpoint Monitoring Agent
echo [*] Initializing Endpoint Monitoring Agent Engine...
start "EDR Agent Engine" /min cmd /k "python agent/agent.py"

:: 3. Launch Web Dashboard
echo [*] Launching SOC Operations Web Console...
start "" "%~dp0frontend\index.html"

echo.
echo ================================================================
echo   [SUCCESS] SOC EDR Subsystems are fully operational!
echo   [+] Run 'stop_edr.bat' to cleanly terminate all services.
echo ================================================================
echo.
timeout /t 3 >nul
exit