@echo off
rem ============================================================
rem  Site Audit - Windows launcher
rem  Double-click this file. It runs site_audit.py in interactive
rem  mode: enter a website, choose a scan type, and an HTML report
rem  is saved to Documents\SiteAudit-Reports and opened.
rem ============================================================
chcp 65001 >nul
title Site Audit
cd /d "%~dp0"

if not exist "site_audit.py" (
    echo site_audit.py was not found next to this file.
    echo Keep site-audit-windows.bat and site_audit.py in the same folder.
    echo.
    pause
    exit /b 1
)

rem Prefer the official Python launcher "py"; fall back to "python".
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 site_audit.py --interactive
    exit /b %errorlevel%
)

python --version >nul 2>nul
if %errorlevel%==0 (
    python site_audit.py --interactive
    exit /b %errorlevel%
)

echo Python 3 is not installed on this computer.
echo.
echo 1. Download it from https://www.python.org/downloads/
echo 2. During setup, tick "Add python.exe to PATH".
echo 3. Then double-click this file again.
echo.
start "" https://www.python.org/downloads/
pause
exit /b 1
