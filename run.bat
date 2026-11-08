@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "ROOT=%CD%"

rem Project-local tools (Windows builds). Missing folders are harmless.
set "PATH=%ROOT%\tools\windows\mingw64\bin;%ROOT%\tools\windows\w64devkit\bin;%ROOT%\tools\windows\binutils\bin;%PATH%"
if exist "%ROOT%\tools\windows\jdk25\bin\java.exe" set "JAVA_HOME=%ROOT%\tools\windows\jdk25"

rem Pick a real Python >= 3.11. Do not rely on "py -3": on Windows the
rem launcher may still point at an older 3.x even after a newer Python is
rem installed. Try explicit versions, then the python.exe on PATH.
set "PYTHON="
where py >nul 2>nul
if not errorlevel 1 (
    call :try_py 3.15
    call :try_py 3.14
    call :try_py 3.13
    call :try_py 3.12
    call :try_py 3.11
)
if not defined PYTHON call :try_python
if not defined PYTHON goto :badpython

start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; try { Start-Process 'http://127.0.0.1:8765/' -ErrorAction Stop } catch { Write-Output 'Browser could not be opened automatically. Visit http://127.0.0.1:8765/ in your browser.' }"
%PYTHON% app.py
goto :end

:try_py
if defined PYTHON exit /b 0
py -%1 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if not errorlevel 1 set "PYTHON=py -%1"
exit /b 0

:try_python
if defined PYTHON exit /b 0
where python >nul 2>nul
if errorlevel 1 exit /b 0
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if not errorlevel 1 set "PYTHON=python"
exit /b 0

:badpython
echo.
echo Python 3.11 or newer was not found.
echo.
echo Installed Python launchers:
py -0p 2>nul
echo.
echo python on PATH:
where python 2>nul
echo.
echo Install Python from https://www.python.org/downloads/windows/
echo During installation, enable "Add python.exe to PATH" and the py launcher.
echo If a newer Python is already installed, run this file from a new Command
echo Prompt, or try: py -3.14 app.py
echo.
pause
exit /b 1

:end
echo.
echo The local workbench has stopped.
pause
