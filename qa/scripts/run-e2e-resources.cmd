@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
cd /d "%ROOT%" || exit /b 1
set "PYTHONDONTWRITEBYTECODE=1"

set "MODE=quick"
if /I "%~1"=="--soak" set "MODE=soak"
if /I "%~1"=="--quick" set "MODE=quick"
if not "%~1"=="" if /I not "%~1"=="--quick" if /I not "%~1"=="--soak" (
    echo Usage: qa\scripts\run-e2e-resources.cmd [--quick^|--soak]
    exit /b 2
)

call :require cargo Cargo
if errorlevel 1 exit /b 1
call :require rustup rustup
if errorlevel 1 exit /b 1
call :require wasm-pack wasm-pack
if errorlevel 1 exit /b 1
call :require node Node.js
if errorlevel 1 exit /b 1
call :require npm npm
if errorlevel 1 exit /b 1

call "qa\scripts\load-e2e-networks.cmd"
if errorlevel 1 exit /b 1

call :run_python qa\scripts\check_capability_parity.py
if errorlevel 1 exit /b 1
call :run_python qa\scripts\check_resource_coverage.py
if errorlevel 1 exit /b 1

echo ==^> Native leak/CPU/resource profiles ^(%MODE%^)
call :run_python qa\scripts\run_resource_probe.py --mode %MODE%
if errorlevel 1 exit /b 1

set "WORK=%TEMP%\kaspa-portal-resources-%RANDOM%-%RANDOM%"
set "BROWSER=%WORK%\browser"
set "SITE=%WORK%\site"
set "PARITY=%WORK%\parity.json"
set "RESOURCE_JSON=%WORK%\resource-profiles.json"
set "TARGET=%WORK%\target"
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%BROWSER%" || exit /b 1
mkdir "%SITE%" || exit /b 1
mkdir "%TARGET%" || exit /b 1
xcopy /e /i /q /y "qa\e2e\browser\*" "%BROWSER%\" >nul || goto :fail
copy /y "qa\e2e\browser\site\index.html" "%SITE%\index.html" >nul || goto :fail
if exist "%BROWSER%\site" rmdir /s /q "%BROWSER%\site"

set "CARGO_BUILD_JOBS=1"
set "CARGO_INCREMENTAL=0"
set "CARGO_PROFILE_DEV_DEBUG=0"
set "CARGO_PROFILE_TEST_DEBUG=0"
set "CARGO_PROFILE_DEV_CODEGEN_UNITS=4"
set "CARGO_PROFILE_TEST_CODEGEN_UNITS=4"
set "CARGO_TARGET_DIR=%TARGET%"

call :run rustup target add wasm32-unknown-unknown
if errorlevel 1 goto :fail

echo ==^> Native WebSocket fault-injection E2E
call :run cargo test --manifest-path qa\Cargo.toml --test e2e-network-fault-injection -- --nocapture
if errorlevel 1 goto :fail

echo ==^> Browser resource E2E: building the real WASM package
call :run wasm-pack build "%ROOT%" --target web --release --out-dir "%SITE%\pkg" --out-name kaspa_portal --features wasm,secret-export
if errorlevel 1 goto :fail

echo ==^> Browser resource E2E: generating canonical fixture
call :run cargo run --manifest-path qa\Cargo.toml --bin browser_parity_fixture -- "%PARITY%"
if errorlevel 1 goto :fail
call :run_python qa\scripts\export_resource_profiles.py --mode %MODE% --output "%RESOURCE_JSON%"
if errorlevel 1 goto :fail

echo ==^> Browser resource E2E: building local fault server
call :run cargo build --manifest-path qa\Cargo.toml --release --bin fault_server
if errorlevel 1 goto :fail
set "KASPA_PORTAL_FAULT_SERVER_BIN=%TARGET%\release\fault_server.exe"
set "KASPA_PORTAL_E2E_SITE=%SITE%"
set "KASPA_PORTAL_E2E_PARITY_FIXTURE=%PARITY%"
set "KASPA_PORTAL_RESOURCE_PROFILES=%RESOURCE_JSON%"

pushd "%BROWSER%" || goto :fail
call :run call npm install --ignore-scripts --no-audit --no-fund --no-package-lock
if errorlevel 1 goto :pop_fail
if not "%KASPA_PORTAL_E2E_SKIP_BROWSER_INSTALL%"=="1" (
    call :run call npx playwright install chromium
    if errorlevel 1 goto :pop_fail
)
echo ==^> Chromium WASM heap/backing-store/CPU/DOM + fault-injection E2E ^(%MODE%^)
call :run call npx playwright test resources.spec.mjs faults.spec.mjs --project=chromium
if errorlevel 1 goto :pop_fail
popd

echo PASS 4 RESOURCE/FAULT %MODE% GATE: PASS
set "RC=0"
goto :cleanup

:pop_fail
set "RC=%ERRORLEVEL%"
popd
if "%RC%"=="0" set "RC=1"
goto :cleanup

:fail
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" set "RC=1"

:cleanup
if exist "%WORK%" rmdir /s /q "%WORK%"
exit /b %RC%

:require
where %1 >nul 2>&1
if errorlevel 1 (
    echo ERROR: %2 is required for Pass 4 resource E2E.
    exit /b 1
)
exit /b 0

:run_python
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python %*
    exit /b !ERRORLEVEL!
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run py -3 %*
    exit /b !ERRORLEVEL!
)
python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python3 %*
    exit /b !ERRORLEVEL!
)
echo ERROR: Python 3.8 or newer is required for Pass 4 resource E2E.
exit /b 1

:run
echo + %*
%*
set "RUN_RC=%ERRORLEVEL%"
if not "%RUN_RC%"=="0" (
    echo ERROR: Command failed with exit code %RUN_RC%: %*
    exit /b %RUN_RC%
)
exit /b 0
