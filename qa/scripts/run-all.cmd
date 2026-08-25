@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
cd /d "%ROOT%" || exit /b 1
set "PYTHONDONTWRITEBYTECODE=1"

set "RESUME_STAGE=full"
set "RUST_E2E_RESUME_ARG="
if /I "%~1"=="--from-wasm" (
    set "RESUME_STAGE=wasm"
    shift
) else if /I "%~1"=="--from-formatting" (
    set "RESUME_STAGE=formatting"
    shift
) else if /I "%~1"=="--from-rust-e2e" (
    set "RESUME_STAGE=rust-e2e"
    shift
) else if /I "%~1"=="--from-live-e2e" (
    set "RESUME_STAGE=live-e2e"
    set "RUST_E2E_RESUME_ARG=--from-live"
    shift
) else if /I "%~1"=="--from-funded-e2e" (
    set "RESUME_STAGE=funded-e2e"
    set "RUST_E2E_RESUME_ARG=--from-funded"
    shift
) else if /I "%~1"=="--from-browser-e2e" (
    set "RESUME_STAGE=browser-e2e"
    shift
) else if /I "%~1"=="--from-resources-e2e" (
    set "RESUME_STAGE=resources-e2e"
    shift
)
if not "%~1"=="" (
    echo ERROR: Unsupported run-all argument: %~1
    echo Supported resume options: --from-wasm, --from-formatting, --from-rust-e2e, --from-live-e2e, --from-funded-e2e, --from-browser-e2e, --from-resources-e2e
    exit /b 2
)

if /I "%RESUME_STAGE%"=="wasm" goto :cargo_setup
if /I "%RESUME_STAGE%"=="formatting" goto :cargo_setup
if /I "%RESUME_STAGE%"=="rust-e2e" goto :cargo_setup
if /I "%RESUME_STAGE%"=="live-e2e" goto :cargo_setup
if /I "%RESUME_STAGE%"=="funded-e2e" goto :cargo_setup
if /I "%RESUME_STAGE%"=="browser-e2e" goto :cargo_setup
if /I "%RESUME_STAGE%"=="resources-e2e" goto :cargo_setup

call :run_python "qa\scripts\cleanup_windows_progress_artifacts.py"
if errorlevel 1 exit /b 1
echo ==^> Kaspa Portal static QA
call :run_python "qa\scripts\check_project.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_versions.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_architecture.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_srp.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_duplication.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_complexity.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_capability_parity.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_rust_e2e_coverage.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_wasm_e2e_coverage.py"
if errorlevel 1 exit /b 1
call :run_python "qa\scripts\check_resource_coverage.py"
if errorlevel 1 exit /b 1

where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is required for the NIST reference suite.
    exit /b 1
)
call :run node qa\tests\randomness\nist\run.mjs
if errorlevel 1 exit /b 1

:cargo_setup
where cargo >nul 2>&1
if errorlevel 1 (
    echo ERROR: Cargo is required because run-all includes the full Rust and browser/WASM E2E gates.
    exit /b 1
)

set "CARGO_BUILD_JOBS=1"
set "CARGO_INCREMENTAL=0"
set "CARGO_PROFILE_DEV_DEBUG=0"
set "CARGO_PROFILE_TEST_DEBUG=0"
set "CARGO_PROFILE_DEV_CODEGEN_UNITS=4"
set "CARGO_PROFILE_TEST_CODEGEN_UNITS=4"
echo ==^> Windows low-memory Cargo settings: 1 job, debug info off, incremental off

if /I "%RESUME_STAGE%"=="wasm" goto :wasm_compile_qa
if /I "%RESUME_STAGE%"=="formatting" goto :formatting_qa
if /I "%RESUME_STAGE%"=="rust-e2e" goto :rust_e2e_qa
if /I "%RESUME_STAGE%"=="live-e2e" goto :rust_e2e_qa
if /I "%RESUME_STAGE%"=="funded-e2e" goto :rust_e2e_qa
if /I "%RESUME_STAGE%"=="browser-e2e" goto :browser_e2e_qa
if /I "%RESUME_STAGE%"=="resources-e2e" goto :resource_e2e_qa

echo ==^> Rust compile/test QA
call :run cargo check --all-targets --all-features
if errorlevel 1 exit /b 1
call :run cargo test --all-targets
if errorlevel 1 exit /b 1
call :run cargo test --doc
if errorlevel 1 exit /b 1
call :run cargo test --manifest-path qa\Cargo.toml --all-targets
if errorlevel 1 exit /b 1
call :run cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 exit /b 1
call :run cargo test --manifest-path qa\benches\Cargo.toml --no-run
if errorlevel 1 exit /b 1
call :run cargo check --manifest-path qa\tests\fuzz\Cargo.toml
if errorlevel 1 exit /b 1

:wasm_compile_qa
where rustup >nul 2>&1
if errorlevel 1 (
    echo ERROR: rustup is required because run-all includes the browser/WASM E2E gate.
    exit /b 1
)
echo ==^> WASM compile QA
call :run rustup target add wasm32-unknown-unknown
if errorlevel 1 exit /b 1
call :run cargo check --target wasm32-unknown-unknown --features wasm
if errorlevel 1 exit /b 1

:formatting_qa
echo ==^> Formatting QA
cargo fmt --version >nul 2>&1
if errorlevel 1 (
    echo RUSTFMT: SKIPPED ^(cargo fmt unavailable^)
) else (
    call :run cargo fmt --all -- --check
    if errorlevel 1 exit /b 1
)

:rust_e2e_qa
call "qa\scripts\load-e2e-networks.cmd"
if errorlevel 1 exit /b 1
call "qa\scripts\prepare-e2e-funding.cmd" standard
if errorlevel 1 exit /b 1
call "qa\scripts\prepare-e2e-funding.cmd" covenant
if errorlevel 1 exit /b 1
echo ==^> Full Rust E2E
call "qa\scripts\run-e2e-rust.cmd" %RUST_E2E_RESUME_ARG%
if errorlevel 1 exit /b 1

:browser_e2e_qa
call "qa\scripts\load-e2e-networks.cmd"
if errorlevel 1 exit /b 1
if /I "%RESUME_STAGE%"=="browser-e2e" (
    call "qa\scripts\prepare-e2e-funding.cmd" standard
    if errorlevel 1 exit /b 1
    call "qa\scripts\prepare-e2e-funding.cmd" covenant
    if errorlevel 1 exit /b 1
)
echo ==^> Full browser/WASM E2E
call "qa\scripts\run-e2e-browser.cmd"
if errorlevel 1 exit /b 1

:resource_e2e_qa
call "qa\scripts\load-e2e-networks.cmd"
if errorlevel 1 exit /b 1
echo ==^> Quick resource/fault E2E
call "qa\scripts\run-e2e-resources.cmd" --quick
if errorlevel 1 exit /b 1

if "%KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED%"=="1" if "%KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED%"=="1" (
    echo ALL NON-FUNDED QA + E2E GATES: PASS
    echo NOTE: both funded network roles were skipped at user request or by network safety policy.
    exit /b 0
)
echo ALL SELECTED QA + E2E GATES: PASS
if "%KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED%"=="1" echo NOTE: funded standard-network scenarios on %KASPA_PORTAL_E2E_STANDARD_NETWORK% were skipped.
if "%KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED%"=="1" echo NOTE: funded covenant-network scenarios on %KASPA_PORTAL_E2E_COVENANT_NETWORK% were skipped.
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
echo ERROR: Python 3.8 or newer is required to run Kaspa Portal QA.
exit /b 1

:run
echo + %*
%*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo ERROR: Command failed with exit code %RC%: %*
    exit /b %RC%
)
exit /b 0
