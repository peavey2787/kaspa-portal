@echo off
setlocal EnableExtensions
cd /d "%~dp0" || (
    echo ERROR: Could not enter the Kaspa Portal repository directory.
    pause
    exit /b 1
)

call "qa\scripts\run-all.cmd" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
    echo Kaspa Portal QA finished successfully.
) else (
    echo Kaspa Portal QA FAILED with exit code %RC%.
)
echo.
pause
exit /b %RC%
