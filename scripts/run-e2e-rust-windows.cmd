@echo off
setlocal EnableExtensions
cd /d "%~dp0.." || (
    echo ERROR: Could not enter the Kaspa Portal repository directory.
    pause
    exit /b 1
)

call "qa\scripts\run-e2e-rust.cmd" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
    echo Kaspa Portal Rust E2E finished successfully.
) else (
    echo Kaspa Portal Rust E2E FAILED with exit code %RC%.
)
echo.
pause
exit /b %RC%
