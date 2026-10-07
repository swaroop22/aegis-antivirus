@echo off
REM ==============================================================================
REM Aegis Defender Pro - Unified Launcher for Windows 10 / 11 / Server
REM ==============================================================================

echo ======================================================================
echo     [+] AEGIS DEFENDER PRO - NEXT-GEN ANTIVIRUS & ENDPOINT SHIELD    
echo ======================================================================
echo   Starting Core Engine and Cyber Command Dashboard...

set PORT=8787

where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% neq 0 (
        echo [-] Error: Python 3 was not detected in PATH. Please install Python 3.
        pause
        exit /b 1
    ) else (
        set PYTHON_CMD=py
    )
) else (
    set PYTHON_CMD=python
)

echo [+] Launching browser to http://localhost:%PORT% ...
start http://localhost:%PORT%

echo [+] Starting Aegis Engine Core...
%PYTHON_CMD% server.py %PORT%
pause
