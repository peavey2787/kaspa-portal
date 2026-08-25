#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MODE="quick"
if [[ "${1:-}" == "--soak" ]]; then
  MODE="soak"
elif [[ -n "${1:-}" && "${1:-}" != "--quick" ]]; then
  echo "Usage: qa/scripts/run-e2e-resources.sh [--quick|--soak]" >&2
  exit 2
fi

for tool in python3 cargo rustup wasm-pack node npm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: $tool is required for Pass 4 resource E2E." >&2
    exit 1
  fi
done

source qa/scripts/load-e2e-networks.sh

python3 qa/scripts/check_capability_parity.py
python3 qa/scripts/check_resource_coverage.py

echo "==> Native leak/CPU/resource profiles ($MODE)"
python3 qa/scripts/run_resource_probe.py --mode "$MODE"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kaspa-portal-resources.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

BROWSER="$WORK/browser"
SITE="$WORK/site"
PARITY="$WORK/parity.json"
RESOURCE_JSON="$WORK/resource-profiles.json"
TARGET="$WORK/target"
mkdir -p "$BROWSER" "$SITE" "$TARGET"
cp -R qa/e2e/browser/. "$BROWSER/"
cp qa/e2e/browser/site/index.html "$SITE/index.html"
rm -rf "$BROWSER/site"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="$TARGET"

rustup target add wasm32-unknown-unknown

echo "==> Native WebSocket fault-injection E2E"
cargo test --manifest-path qa/Cargo.toml --test e2e-network-fault-injection -- --nocapture

echo "==> Browser resource E2E: building the real WASM package"
wasm-pack build "$ROOT" \
  --target web \
  --release \
  --out-dir "$SITE/pkg" \
  --out-name kaspa_portal \
  --features wasm,secret-export

echo "==> Browser resource E2E: generating canonical fixture"
cargo run --manifest-path qa/Cargo.toml --bin browser_parity_fixture -- "$PARITY"
python3 qa/scripts/export_resource_profiles.py --mode "$MODE" --output "$RESOURCE_JSON"

echo "==> Browser resource E2E: building local fault server"
cargo build --manifest-path qa/Cargo.toml --release --bin fault_server
FAULT_SERVER="$TARGET/release/fault_server"
if [[ "$(uname -s 2>/dev/null || true)" == MINGW* || "$(uname -s 2>/dev/null || true)" == MSYS* ]]; then
  FAULT_SERVER="$FAULT_SERVER.exe"
fi

export KASPA_PORTAL_E2E_SITE="$SITE"
export KASPA_PORTAL_E2E_PARITY_FIXTURE="$PARITY"
export KASPA_PORTAL_RESOURCE_PROFILES="$RESOURCE_JSON"
export KASPA_PORTAL_FAULT_SERVER_BIN="$FAULT_SERVER"

pushd "$BROWSER" >/dev/null
npm install --ignore-scripts --no-audit --no-fund --no-package-lock
if [[ "${KASPA_PORTAL_E2E_SKIP_BROWSER_INSTALL:-0}" != "1" ]]; then
  npx playwright install chromium
fi

echo "==> Chromium WASM heap/backing-store/CPU/DOM + fault-injection E2E ($MODE)"
npx playwright test resources.spec.mjs faults.spec.mjs --project=chromium
popd >/dev/null

echo "PASS 4 RESOURCE/FAULT ${MODE^^} GATE: PASS"
