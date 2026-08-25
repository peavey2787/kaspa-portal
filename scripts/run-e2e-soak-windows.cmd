@echo off
setlocal EnableExtensions
cd /d "%~dp0.." || (
    echo ERROR: Could not enter the Kaspa Portal repository directory.
    pause
    exit /b 1
)
call "qa\scripts\run-e2e-resources.cmd" --soak
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (echo Kaspa Portal resource/fault soak finished successfully.) else (echo Kaspa Portal resource/fault soak FAILED with exit code %RC%.)
echo.
pause
exit /b %RC%
