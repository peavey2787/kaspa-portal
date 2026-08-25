@echo off
rem CALL this file so the selected variables remain in the caller's environment.
if "%KASPA_PORTAL_E2E_NETWORKS_RESOLVED%"=="1" exit /b 0
for %%I in ("%~dp0..\..") do set "NETWORK_ROOT=%%~fI"
set "NETWORK_ENV_FILE=%TEMP%\kaspa-portal-e2e-networks-%RANDOM%-%RANDOM%.env"

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    python "%NETWORK_ROOT%\qa\scripts\select_e2e_network.py" --prompt --output "%NETWORK_ENV_FILE%"
    set "NETWORK_RC=%ERRORLEVEL%"
    goto :network_python_done
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 "%NETWORK_ROOT%\qa\scripts\select_e2e_network.py" --prompt --output "%NETWORK_ENV_FILE%"
    set "NETWORK_RC=%ERRORLEVEL%"
    goto :network_python_done
)
python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    python3 "%NETWORK_ROOT%\qa\scripts\select_e2e_network.py" --prompt --output "%NETWORK_ENV_FILE%"
    set "NETWORK_RC=%ERRORLEVEL%"
    goto :network_python_done
)
echo ERROR: Python 3.8 or newer is required to select E2E networks.
exit /b 1

:network_python_done
if not "%NETWORK_RC%"=="0" (
    if exist "%NETWORK_ENV_FILE%" del /q "%NETWORK_ENV_FILE%" >nul 2>&1
    exit /b %NETWORK_RC%
)
for /f "usebackq tokens=1,* delims==" %%A in ("%NETWORK_ENV_FILE%") do set "%%A=%%B"
del /q "%NETWORK_ENV_FILE%" >nul 2>&1
if not "%KASPA_PORTAL_E2E_NETWORKS_RESOLVED%"=="1" (
    echo ERROR: E2E network selector did not produce a complete environment.
    exit /b 1
)
exit /b 0
