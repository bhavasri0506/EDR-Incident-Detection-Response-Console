@echo off
title EDR Adversary Attack Simulation Suite
color 0C
echo ================================================================
echo   [!] SIMULATING REAL-TIME ADVERSARY ATTACK SCENARIOS
echo   [!] Testing Endpoint Detection and Response Capabilities...
echo ================================================================
echo.

:: Vector 1: PowerShell Obfuscated Payload (Keep alive so Agent catches it)
echo [*] Triggering Vector 1: Obfuscated PowerShell Execution...
start "Malicious PowerShell" powershell.exe -NoProfile -enc aGVsbG8= -Command "Start-Sleep -Seconds 10"
timeout /t 2 /nobreak >nul

:: Vector 2: Mimikatz Credential Dumping Emulation
echo [*] Triggering Vector 2: Mimikatz Memory Dump Emulation...
start "Mimikatz Simulation" cmd.exe /k "echo mimikatz privilege::debug && ping 127.0.0.1 -n 10 >nul && exit"
timeout /t 2 /nobreak >nul

:: Vector 3: Shadow Copy Deletion (vssadmin)
echo [*] Triggering Vector 3: Ransomware Recovery Inhibition (vssadmin)...
start "VSSAdmin Simulation" cmd.exe /k "echo vssadmin delete shadows /all /quiet && ping 127.0.0.1 -n 10 >nul && exit"

echo.
echo ================================================================
echo   [SUCCESS] Persistent attack vectors dispatched!
echo   [+] Inspect EDR Agent console for instant termination.
echo   [+] Observe SOC Dashboard for emergency red alert banner.
echo ================================================================
echo.
pause