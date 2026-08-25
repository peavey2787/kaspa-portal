@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
cd /d "%ROOT%" || exit /b 1
set "PYTHONDONTWRITEBYTECODE=1"

set "MODE=full"
if /I "%~1"=="--read-only" set "MODE=read-only"
if not "%~1"=="" if /I not "%~1"=="--read-only" (
    echo Usage: qa\scripts\run-e2e-browser.cmd [--read-only]
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
call :run_python "qa\scripts\check_capability_parity.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_wasm_e2e_coverage.py"
if errorlevel 1 exit /b 1

if /I "%MODE%"=="read-only" (
    set "KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED=1"
    set "KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED=1"
) else (
    call "qa\scripts\prepare-e2e-funding.cmd" standard
    if errorlevel 1 exit /b 1
    call "qa\scripts\prepare-e2e-funding.cmd" covenant
    if errorlevel 1 exit /b 1
)

set "WORK=%TEMP%\kaspa-portal-browser-e2e-%RANDOM%-%RANDOM%"
set "BROWSER=%WORK%\browser"
set "SITE=%WORK%\site"
set "PARITY=%WORK%\parity.json"
set "FUNDED=%WORK%\funded.json"
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%BROWSER%" || exit /b 1
mkdir "%SITE%" || exit /b 1
xcopy /e /i /q /y "qa\e2e\browser\*" "%BROWSER%\" >nul || goto :fail
copy /y "qa\e2e\browser\site\index.html" "%SITE%\index.html" >nul || goto :fail
if exist "%BROWSER%\site" rmdir /s /q "%BROWSER%\site"

set "CARGO_BUILD_JOBS=1"
set "CARGO_INCREMENTAL=0"
set "CARGO_PROFILE_DEV_DEBUG=0"
set "CARGO_PROFILE_TEST_DEBUG=0"
set "CARGO_PROFILE_DEV_CODEGEN_UNITS=4"
set "CARGO_PROFILE_TEST_CODEGEN_UNITS=4"

call :run rustup target add wasm32-unknown-unknown
if errorlevel 1 goto :fail

echo ==^> Browser E2E: building the real WASM package
call :run wasm-pack build "%ROOT%" --target web --release --out-dir "%SITE%\pkg" --out-name kaspa_portal --features wasm,secret-export
if errorlevel 1 goto :fail

echo ==^> Browser E2E: generating canonical Rust parity fixture
call :run cargo run --manifest-path qa\Cargo.toml --bin browser_parity_fixture -- "%PARITY%"
if errorlevel 1 goto :fail

set "KASPA_PORTAL_E2E_SITE=%SITE%"
set "KASPA_PORTAL_E2E_PARITY_FIXTURE=%PARITY%"
set "KASPA_PORTAL_E2E_FUNDED_FIXTURE="
if not "%KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED%"=="1" goto :prepare_browser_funded
if not "%KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED%"=="1" goto :prepare_browser_funded
goto :browser_funded_done

:prepare_browser_funded
echo ==^> Browser E2E: preparing funded standard/covenant fixture
call :run cargo run --manifest-path qa\Cargo.toml --bin browser_funded_fixture -- "%FUNDED%"
if errorlevel 1 goto :fail
set "KASPA_PORTAL_E2E_FUNDED_FIXTURE=%FUNDED%"
:browser_funded_done

pushd "%BROWSER%" || goto :fail
call :run call npm install --ignore-scripts --no-audit --no-fund --no-package-lock
if errorlevel 1 goto :pop_fail
if not "%KASPA_PORTAL_E2E_SKIP_BROWSER_INSTALL%"=="1" (
    call :run call npx playwright install chromium firefox webkit
    if errorlevel 1 goto :pop_fail
)
echo ==^> Browser E2E: Playwright Chromium + Firefox + WebKit
call :run call npx playwright test offline.spec.mjs live.spec.mjs funded.spec.mjs storage.spec.mjs cross-browser.spec.mjs
if errorlevel 1 goto :pop_fail
popd

echo ALL SELECTED BROWSER/WASM E2E GATES: PASS
if "%KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED%"=="1" echo NOTE: funded standard-network browser scenarios were skipped.
if "%KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED%"=="1" echo NOTE: funded covenant-network browser scenarios were skipped.
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
    echo ERROR: %2 is required for browser/WASM E2E.
    exit /b 1
)
exit /b 0

:run_python
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python %1
    exit /b !ERRORLEVEL!
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run py -3 %1
    exit /b !ERRORLEVEL!
)
python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python3 %1
    exit /b !ERRORLEVEL!
)
echo ERROR: Python 3.8 or newer is required for E2E capability checks.
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
