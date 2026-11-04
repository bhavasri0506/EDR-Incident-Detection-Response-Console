@echo off
title SOC EDR Enterprise Auto-Deployer
color 0A
echo ================================================================
echo   [+] SOC EDR Telemetry and Incident Response System
echo   [+] Initializing Automated Deployment Environment...
echo ================================================================
echo.

cd /d "%~dp0"

:: 1. Verify Python Environment
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Python runtime environment not detected!
        echo Please ensure Python 3.8+ is installed and configured in system PATH.
        echo.
        pause
        exit /b
    )
)

:: 2. Verify and Install Dependencies
echo [*] Verifying core framework dependencies...
python -m pip install fastapi uvicorn psutil requests pydantic --quiet --no-warn-script-location

echo [+] Dependencies verified successfully.
echo.

:: 3. Launch Telemetry Ingestion Server
echo [*] Deploying Telemetry Ingestion Server (Port 5000)...
start "EDR Backend Server" cmd /k "python server/server.py"

:: Allow 3 seconds for database initialization
timeout /t 3 /nobreak >nul

:: 4. Launch Endpoint Detection and Response Agent
echo [*] Activating Real-Time Endpoint Surveillance Engine...
start "EDR Agent Engine" cmd /k "python agent/agent.py"

:: 5. Launch SOC Visual Web Dashboard
echo [*] Opening SOC Operations Console in default browser...
start "" "%~dp0frontend\index.html"

echo.
echo ================================================================
echo   [SUCCESS] All EDR Engine Subsystems are Live and Operational!
echo   [+] Host Telemetry and Active Defense are running.
echo   [+] Execute 'stop_edr.bat' to safely terminate all instances.
echo ================================================================
echo.
timeout /t 4 >nul
exit