@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
cd /d "%ROOT%" || exit /b 1
set "PYTHONDONTWRITEBYTECODE=1"

set "MODE=full"
set "START_STAGE=offline"
:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="--read-only" (
    set "MODE=read-only"
) else if /I "%~1"=="--from-live" (
    set "START_STAGE=live"
) else if /I "%~1"=="--from-funded" (
    set "START_STAGE=funded"
) else (
    echo Usage: qa\scripts\run-e2e-rust.cmd [--from-live] [--from-funded] [--read-only]
    exit /b 2
)
shift
goto :parse_args
:args_done

call "qa\scripts\load-e2e-networks.cmd"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_capability_parity.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_rust_e2e_coverage.py"
if errorlevel 1 exit /b 1

set "CARGO_BUILD_JOBS=1"
set "CARGO_INCREMENTAL=0"
set "CARGO_PROFILE_DEV_DEBUG=0"
set "CARGO_PROFILE_TEST_DEBUG=0"
set "CARGO_PROFILE_DEV_CODEGEN_UNITS=4"
set "CARGO_PROFILE_TEST_CODEGEN_UNITS=4"

if /I "%MODE%"=="read-only" (
    set "KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED=1"
    set "KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED=1"
) else (
    call "qa\scripts\prepare-e2e-funding.cmd" standard
    if errorlevel 1 exit /b 1
    call "qa\scripts\prepare-e2e-funding.cmd" covenant
    if errorlevel 1 exit /b 1
)

if /I "%START_STAGE%"=="funded" goto :funded_e2e
if /I "%START_STAGE%"=="live" goto :live_e2e
echo ==^> Rust E2E: offline facade workflows ^(standard=%KASPA_PORTAL_E2E_STANDARD_NETWORK%, covenant=%KASPA_PORTAL_E2E_COVENANT_NETWORK%^)
call :run cargo test --manifest-path qa\Cargo.toml --test e2e-rust-offline -- --ignored --nocapture --test-threads=1
if errorlevel 1 exit /b 1

:live_e2e
echo ==^> Rust E2E: public %KASPA_PORTAL_E2E_STANDARD_NETWORK% read-only workflows
call :run cargo test --manifest-path qa\Cargo.toml --test e2e-rust-live-network -- --ignored --nocapture --test-threads=1
if errorlevel 1 exit /b 1

:funded_e2e
if "%KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED%"=="1" (
    echo NOTE: funded standard-network workflows on %KASPA_PORTAL_E2E_STANDARD_NETWORK% were skipped.
) else (
    echo ==^> Rust E2E: funded ordinary workflows on %KASPA_PORTAL_E2E_STANDARD_NETWORK%
    call :run cargo test --manifest-path qa\Cargo.toml --test e2e-rust-funded-networks rust_funded_standard_network_transactions -- --ignored --nocapture --test-threads=1
    if errorlevel 1 exit /b 1
)

if "%KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED%"=="1" (
    echo NOTE: funded covenant workflows on %KASPA_PORTAL_E2E_COVENANT_NETWORK% were skipped.
) else (
    echo ==^> Rust E2E: funded covenant workflows on %KASPA_PORTAL_E2E_COVENANT_NETWORK%
    call :run cargo test --manifest-path qa\Cargo.toml --test e2e-rust-funded-networks rust_funded_covenant_network_transactions -- --ignored --nocapture --test-threads=1
    if errorlevel 1 exit /b 1
)

echo ALL SELECTED RUST E2E GATES: PASS
exit /b 0

:run_python
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python %1
    exit /b %ERRORLEVEL%
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run py -3 %1
    exit /b %ERRORLEVEL%
)
python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 (
    call :run python3 %1
    exit /b %ERRORLEVEL%
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
