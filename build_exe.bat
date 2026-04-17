@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  SNI-Proxy - Build Standalone Executable
echo ============================================================
echo.

:: ---- Check Python ----
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found. Install Python 3.11+ and make sure it is on PATH.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [INFO] Using %%v

:: ---- Check pip ----
python -m pip --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] pip not found. Run: python -m ensurepip --upgrade
    pause
    exit /b 1
)

:: ---- Install / upgrade PyInstaller ----
echo.
echo [STEP 1] Installing / upgrading PyInstaller...
python -m pip install --upgrade pyinstaller
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install PyInstaller.
    pause
    exit /b 1
)

:: ---- Install project dependencies (needed for PyInstaller to analyse imports) ----
echo.
echo [STEP 2] Installing project dependencies...
python -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install project requirements.
    pause
    exit /b 1
)

:: ---- Run PyInstaller ----
echo.
echo [STEP 3] Building executable with PyInstaller...
echo         This may take a minute...
echo.

python -m PyInstaller ^
    --onefile ^
    --name sni_proxy ^
    --uac-admin ^
    --collect-all pydivert ^
    --hidden-import colorama ^
    --hidden-import tomllib ^
    --noconfirm ^
    main.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] PyInstaller build failed. See output above for details.
    pause
    exit /b 1
)

:: ---- Copy required data files next to the EXE ----
echo.
echo [STEP 4] Copying data files to dist\...

copy /Y "config.toml"    "dist\config.toml"    >nul
copy /Y "sni_list.txt"   "dist\sni_list.txt"   >nul
copy /Y "cdn_ranges.json" "dist\cdn_ranges.json" >nul

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to copy one or more data files.
    pause
    exit /b 1
)

:: ---- Done ----
echo.
echo ============================================================
echo  BUILD COMPLETE
echo ============================================================
echo.
echo  Output folder : %~dp0dist\
echo.
echo  Files to distribute (keep them all together):
echo    dist\sni_proxy.exe
echo    dist\config.toml
echo    dist\sni_list.txt
echo    dist\cdn_ranges.json
echo.
echo  NOTE: The EXE requires Administrator privileges to run
echo        because WinDivert needs kernel-level access.
echo ============================================================
echo.
pause
