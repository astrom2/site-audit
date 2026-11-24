@echo off
setlocal
rem ============================================================
rem  Site Audit - Windows launcher
rem  Double-click this file. It runs site_audit.py in interactive
rem  mode: enter a website, choose a scan type, and an HTML report
rem  is saved to Documents\SiteAudit-Reports and opened.
rem  If anything goes wrong, this window stays open and says why.
rem ============================================================
chcp 65001 >nul
title Site Audit
cd /d "%~dp0"

echo ==================================================================
echo   Site Audit - Windows launcher
echo   Folder: %~dp0
echo ==================================================================
echo.

rem --- 1) Running from inside a ZIP without extracting? ---
echo %~dp0 | find /i "\Temp\" >nul
if %errorlevel%==0 if not exist "%~dp0site_audit.py" (
    echo It looks like you opened this file directly from inside the ZIP.
    echo Right-click the ZIP file, choose "Extract All...", then open the
    echo extracted folder and double-click site-audit-windows.bat again.
    goto :fail
)

rem --- 2) site_audit.py must be next to this file ---
if not exist "%~dp0site_audit.py" (
    echo site_audit.py was not found in this folder.
    echo Keep site-audit-windows.bat and site_audit.py in the same folder.
    goto :fail
)

rem --- 3) Find a working Python 3 ---
set "PYCMD="
py -3 -c "import sys" >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD python -c "import sys; sys.exit(0 if sys.version_info[0]==3 else 1)" >nul 2>nul && set "PYCMD=python"
if not defined PYCMD python3 -c "import sys" >nul 2>nul && set "PYCMD=python3"

if not defined PYCMD (
    echo Python 3 is not installed, or Windows cannot find it.
    echo.
    echo  1. Download Python from https://www.python.org/downloads/
    echo  2. During setup, tick "Add python.exe to PATH".
    echo  3. Close this window and double-click this file again.
    echo.
    echo Note: the "python" that opens the Microsoft Store is not a real
    echo Python installation.
    start "" https://www.python.org/downloads/
    goto :fail
)

for /f "delims=" %%v in ('%PYCMD% --version 2^>^&1') do echo Using %%v  ^(%PYCMD%^)
echo.

rem --- 4) Run the tool in interactive mode ---
%PYCMD% "%~dp0site_audit.py" --interactive
set "RC=%errorlevel%"

rem 0 = finished normally, 3 = error already shown and confirmed by the user
if "%RC%"=="0" exit /b 0
if "%RC%"=="3" exit /b 3

echo.
echo ------------------------------------------------------------------
echo The tool stopped unexpectedly (exit code %RC%).
echo Please take a screenshot of this window.
echo ------------------------------------------------------------------
goto :fail

:fail
echo.
pause
exit /b 1
