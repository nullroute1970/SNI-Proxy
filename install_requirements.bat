@echo off
echo Installing requirements...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo Installation failed. Make sure Python and pip are installed and accessible.
    pause
    exit /b %ERRORLEVEL%
)
echo Installation complete.
pause
