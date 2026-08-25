@echo off
rem CALL this file with STANDARD or COVENANT; variables persist in the caller.
set "FUND_ROLE=%~1"
if /I "%FUND_ROLE%"=="standard" set "FUND_ROLE=STANDARD"
if /I "%FUND_ROLE%"=="covenant" set "FUND_ROLE=COVENANT"
if /I not "%FUND_ROLE%"=="STANDARD" if /I not "%FUND_ROLE%"=="COVENANT" (
    echo ERROR: funding role must be standard or covenant.
    exit /b 2
)
for %%I in ("%~dp0..\..") do set "FUND_ROOT=%%~fI"
call set "FUND_NETWORK=%%KASPA_PORTAL_E2E_%FUND_ROLE%_NETWORK%%"
call set "FUND_ENDPOINT=%%KASPA_PORTAL_E2E_%FUND_ROLE%_ENDPOINT%%"
call set "FUND_REST_ENDPOINT=%%KASPA_PORTAL_E2E_%FUND_ROLE%_REST_ENDPOINT%%"
call set "FUND_FAUCET=%%KASPA_PORTAL_E2E_%FUND_ROLE%_FAUCET%%"
call set "FUND_SUPPORTED=%%KASPA_PORTAL_E2E_%FUND_ROLE%_FUNDED_SUPPORTED%%"
call set "FUND_VERIFIED=%%KASPA_PORTAL_E2E_%FUND_ROLE%_FUNDED_VERIFIED%%"
call set "FUND_SKIP=%%KASPA_PORTAL_E2E_SKIP_%FUND_ROLE%_FUNDED%%"
if /I "%FUND_NETWORK%"=="mainnet" (
    if "%KASPA_PORTAL_E2E_ALLOW_MAINNET_SPEND%"=="1" (
        set "FUND_SUPPORTED=1"
    ) else (
        set "FUND_SUPPORTED=0"
    )
)
if not "%FUND_SUPPORTED%"=="1" (
    set "KASPA_PORTAL_E2E_SKIP_%FUND_ROLE%_FUNDED=1"
    echo Funded %FUND_ROLE% spending is disabled for %FUND_NETWORK%; read-only coverage will continue.
    exit /b 0
)
if "%FUND_VERIFIED%"=="1" exit /b 0
if "%FUND_SKIP%"=="1" exit /b 0
set "FUND_STATE=%FUND_ROOT%\.kaspa-portal-e2e\wallet.env"

cargo run --quiet --manifest-path qa\Cargo.toml --bin e2e_wallet -- --state-file "%FUND_STATE%" --network "%FUND_NETWORK%" --endpoint "%FUND_ENDPOINT%" --rest-endpoint "%FUND_REST_ENDPOINT%" --faucet "%FUND_FAUCET%"
if errorlevel 1 exit /b %ERRORLEVEL%

:fund_prompt
echo.
choice /C YN /N /M "Have you funded the %FUND_NETWORK% E2E wallet with at least 10 KAS? [Y/N] "
if errorlevel 2 goto :fund_skip
if errorlevel 1 goto :fund_check
echo ERROR: Could not read Y/N funding choice.
exit /b 1

:fund_check
cargo run --quiet --manifest-path qa\Cargo.toml --bin e2e_wallet -- --state-file "%FUND_STATE%" --network "%FUND_NETWORK%" --endpoint "%FUND_ENDPOINT%" --rest-endpoint "%FUND_REST_ENDPOINT%" --faucet "%FUND_FAUCET%" --check-funded
set "FUND_RC=%ERRORLEVEL%"
if "%FUND_RC%"=="0" goto :fund_verified
if "%FUND_RC%"=="10" (
    echo The wallet still needs at least 10 KAS on %FUND_NETWORK%. Fund the address shown above, then press Y; press N to skip only this network's funded tests.
    goto :fund_prompt
)
exit /b %FUND_RC%

:fund_skip
set "KASPA_PORTAL_E2E_SKIP_%FUND_ROLE%_FUNDED=1"
echo Funded %FUND_ROLE% tests on %FUND_NETWORK% will be skipped; the remaining E2E tests will continue.
exit /b 0

:fund_verified
if not "%KASPA_PORTAL_E2E_XPRV%"=="" goto :fund_exported
for /f "usebackq tokens=1,* delims==" %%A in ("%FUND_STATE%") do (
    if /I "%%A"=="KASPA_PORTAL_E2E_XPRV" set "KASPA_PORTAL_E2E_XPRV=%%B"
)
if "%KASPA_PORTAL_E2E_XPRV%"=="" (
    echo ERROR: generated E2E wallet state does not contain KASPA_PORTAL_E2E_XPRV.
    exit /b 1
)
:fund_exported
set "KASPA_PORTAL_E2E_%FUND_ROLE%_FUNDED_VERIFIED=1"
set "KASPA_PORTAL_E2E_SKIP_%FUND_ROLE%_FUNDED="
exit /b 0
