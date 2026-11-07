@echo off
setlocal
cd /d "%~dp0"
echo ReverseShield Windows setup
echo This script downloads project-local tools into tools\windows and tools\ghidra.
echo It does not install anything system-wide and does not require Administrator.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup_windows.ps1"
if errorlevel 1 (
    echo.
    echo Setup did not complete. Read the message above and START_HERE.md.
    pause
    exit /b 1
)
echo.
echo Setup complete. Start the workbench with run.bat.
pause
