#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MODE="full"
if [[ "${1:-}" == "--read-only" ]]; then
  MODE="read-only"
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "Usage: qa/scripts/run-e2e-browser.sh [--read-only]" >&2
  exit 2
fi
for tool in python3 cargo rustup wasm-pack node npm; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is required for browser/WASM E2E." >&2; exit 1; }
done

source qa/scripts/load-e2e-networks.sh
python3 qa/scripts/check_capability_parity.py
python3 qa/scripts/check_wasm_e2e_coverage.py
if [[ "$MODE" == "read-only" ]]; then
  export KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED=1
  export KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED=1
else
  source qa/scripts/prepare-e2e-funding.sh standard
  source qa/scripts/prepare-e2e-funding.sh covenant
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kaspa-portal-browser-e2e.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM
BROWSER="$WORK/browser"
SITE="$WORK/site"
PARITY="$WORK/parity.json"
FUNDED="$WORK/funded.json"
mkdir -p "$BROWSER" "$SITE"
cp -R qa/e2e/browser/. "$BROWSER/"
cp qa/e2e/browser/site/index.html "$SITE/index.html"
rm -rf "$BROWSER/site"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
rustup target add wasm32-unknown-unknown

echo "==> Browser E2E: building the real WASM package"
wasm-pack build "$ROOT" --target web --release --out-dir "$SITE/pkg" --out-name kaspa_portal --features wasm,secret-export

echo "==> Browser E2E: generating canonical Rust parity fixture"
cargo run --manifest-path qa/Cargo.toml --bin browser_parity_fixture -- "$PARITY"
export KASPA_PORTAL_E2E_SITE="$SITE"
export KASPA_PORTAL_E2E_PARITY_FIXTURE="$PARITY"
unset KASPA_PORTAL_E2E_FUNDED_FIXTURE || true
if [[ "${KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED:-0}" != "1" || "${KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED:-0}" != "1" ]]; then
  echo "==> Browser E2E: preparing funded standard/covenant fixture"
  cargo run --manifest-path qa/Cargo.toml --bin browser_funded_fixture -- "$FUNDED"
  export KASPA_PORTAL_E2E_FUNDED_FIXTURE="$FUNDED"
fi

pushd "$BROWSER" >/dev/null
npm install --ignore-scripts --no-audit --no-fund --no-package-lock
if [[ "${KASPA_PORTAL_E2E_SKIP_BROWSER_INSTALL:-0}" != "1" ]]; then
  npx playwright install chromium firefox webkit
fi
echo "==> Browser E2E: Playwright Chromium + Firefox + WebKit"
npx playwright test offline.spec.mjs live.spec.mjs funded.spec.mjs storage.spec.mjs cross-browser.spec.mjs
popd >/dev/null

echo "ALL SELECTED BROWSER/WASM E2E GATES: PASS"
[[ "${KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED:-0}" == "1" ]] && echo "NOTE: funded standard-network browser scenarios were skipped."
[[ "${KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED:-0}" == "1" ]] && echo "NOTE: funded covenant-network browser scenarios were skipped."
