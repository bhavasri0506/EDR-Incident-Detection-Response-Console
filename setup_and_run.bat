@echo off
title SOC EDR Enterprise Auto-Deployer
color 0A
echo ================================================================
echo   [+] SOC EDR Telemetry and Incident Response System
echo   [+] Initializing Cross-Platform Automated Environment...
echo ================================================================
echo.

cd /d "%~dp0"

:: 1. Verify Python Installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Python runtime is not detected on this system!
        echo Please ensure Python 3.8+ is installed and 'Add Python to PATH' is enabled.
        echo.
        pause
        exit /b
    )
)

:: 2. Install Required Dependencies
echo [*] Checking and verifying Python core dependencies...
python -m pip install fastapi uvicorn psutil requests pydantic --quiet --no-warn-script-location

echo [+] Dependencies verified successfully.
echo.

:: 3. Launch Backend Telemetry Server
echo [*] Launching Telemetry Ingestion Server (Port 5000)...
start "EDR Backend Server" cmd /k "python server/server.py"

:: Allow 3 seconds for database initialization and socket binding
timeout /t 3 /nobreak >nul

:: 4. Launch Endpoint Detection and Response Agent
echo [*] Activating EDR Telemetry Agent and Defense Engine...
start "EDR Agent Engine" cmd /k "python agent/agent.py"

:: 5. Launch SOC Visual Web Dashboard
echo [*] Deploying SOC Operations Console to Default Browser...
start "" "%~dp0frontend\index.html"

echo.
echo ================================================================
echo   [SUCCESS] All EDR Engine Subsystems are Live and Operational!
echo   [+] Monitor Host Activity and Live Threats via Console.
echo   [+] Execute 'stop_edr.bat' to safely terminate all instances.
echo ================================================================
echo.
timeout /t 4 >nul
exit