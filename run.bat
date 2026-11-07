@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "ROOT=%CD%"

rem Project-local tools (Windows builds). Missing folders are harmless.
set "PATH=%ROOT%\tools\windows\mingw64\bin;%ROOT%\tools\windows\w64devkit\bin;%ROOT%\tools\windows\binutils\bin;%PATH%"
if exist "%ROOT%\tools\windows\jdk25\bin\java.exe" set "JAVA_HOME=%ROOT%\tools\windows\jdk25"

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
    if errorlevel 1 goto :badpython
    start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:8765/'"
    py -3 app.py
    goto :end
)

where python >nul 2>nul
if errorlevel 1 goto :badpython
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 goto :badpython
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:8765/'"
python app.py
goto :end

:badpython
echo.
echo Python 3.11 or newer was not found.
echo Install Python from https://www.python.org/downloads/windows/
echo During installation, enable "Add python.exe to PATH", then run this file again.
echo.
pause
exit /b 1

:end
echo.
echo The local workbench has stopped.
pause
