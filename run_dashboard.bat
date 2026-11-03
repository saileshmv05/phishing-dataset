@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ======================================================
echo   STARTING PHISHSHIELD AI WEB DASHBOARD
echo ======================================================

if exist "venv\Scripts\python.exe" (
    set "PY=venv\Scripts\python.exe"
) else (
    set "PY=python"
)

echo Launching local server at http://127.0.0.1:5000 ...
echo Your default browser will open automatically in 2 seconds.
echo Press Ctrl+C in this window to stop the server when done.
echo.

"!PY!" app.py
pause
