@echo off
setlocal enabledelayedexpansion

:: Set working directory to the folder containing this batch script
cd /d "%~dp0"

:: Determine Python executable (prefer project venv)
if exist "venv\Scripts\python.exe" (
    set "PY=venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if !errorlevel! equ 0 (
        set "PY=python"
    ) else (
        echo [ERROR] Python not found in 'venv' or in system PATH.
        echo Please ensure Python is installed and configured.
        pause
        exit /b 1
    )
)

:: If a command line parameter was passed, handle direct execution
set "DIRECT_ARG=%~1"
if /i "%DIRECT_ARG%"=="web" goto run_web
if /i "%DIRECT_ARG%"=="gui" goto run_gui
if /i "%DIRECT_ARG%"=="train" goto run_train
if /i "%DIRECT_ARG%"=="build" goto run_build
if /i "%DIRECT_ARG%"=="explore" goto run_explore

:menu
cls
echo ======================================================
echo       PHISHSHIELD AI - PHISHING DETECTION SYSTEM
echo ======================================================
echo  Python environment: !PY!
echo ======================================================
echo  1. Launch Modern Dark Web Dashboard (Recommended)
echo  2. Launch Desktop GUI (gui.py)
echo  3. Train and Evaluate Model (train.py)
echo  4. Rebuild Clean Dataset (build_dataset.py)
echo  5. Quick Explore Raw Datasets (explore.py)
echo  6. Open Virtual Environment Terminal (cmd)
echo  0. Exit
echo ======================================================
set /p choice="Enter your choice [0-6]: "

if "%choice%"=="1" goto run_web
if "%choice%"=="2" goto run_gui
if "%choice%"=="3" goto run_train
if "%choice%"=="4" goto run_build
if "%choice%"=="5" goto run_explore
if "%choice%"=="6" goto run_shell
if "%choice%"=="0" goto end

echo Invalid option. Please try again.
timeout /t 2 >nul
goto menu

:run_web
cls
echo Starting PhishShield AI Web Dashboard...
echo Opening in default browser at http://127.0.0.1:5000 ...
"!PY!" app.py
goto post_run

:run_gui
cls
echo Starting Phishing Detection Desktop GUI...
"!PY!" gui.py
goto post_run

:run_train
cls
echo Running model training and evaluation (TF-IDF + Logistic Regression)...
echo This may take a moment...
echo.
"!PY!" train.py
goto post_run

:run_build
cls
echo Rebuilding dataset.csv from raw CSV files...
echo This will take a few minutes to process all raw datasets...
echo.
"!PY!" build_dataset.py
goto post_run

:run_explore
cls
echo Sampling raw dataset subjects and labels...
echo.
"!PY!" explore.py
goto post_run

:run_shell
cls
echo Opening command prompt with venv activated...
cmd /k "venv\Scripts\activate.bat"
goto menu

:post_run
echo.
echo ======================================================
echo Execution finished.
if defined DIRECT_ARG exit /b 0
pause
goto menu

:end
exit /b 0
