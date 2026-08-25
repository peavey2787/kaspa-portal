#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

resume_stage="full"
case "${1:-}" in
  --from-wasm) resume_stage="wasm"; shift ;;
  --from-formatting) resume_stage="formatting"; shift ;;
  --from-rust-e2e) resume_stage="rust-e2e"; shift ;;
  --from-live-e2e) resume_stage="live-e2e"; shift ;;
  --from-funded-e2e) resume_stage="funded-e2e"; shift ;;
  --from-browser-e2e) resume_stage="browser-e2e"; shift ;;
  --from-resources-e2e) resume_stage="resources-e2e"; shift ;;
esac
if [[ "$#" -ne 0 ]]; then
  echo "ERROR: Unsupported run-all argument: $1" >&2
  echo "Supported resume options: --from-wasm, --from-formatting, --from-rust-e2e, --from-live-e2e, --from-funded-e2e, --from-browser-e2e, --from-resources-e2e" >&2
  exit 2
fi

if [[ "$resume_stage" == "full" ]]; then
  python3 qa/scripts/check_project.py
  python3 qa/scripts/check_versions.py
  python3 qa/scripts/check_architecture.py
  python3 qa/scripts/check_srp.py
  python3 qa/scripts/check_duplication.py
  python3 qa/scripts/check_complexity.py
  python3 qa/scripts/check_capability_parity.py
  python3 qa/scripts/check_rust_e2e_coverage.py
  python3 qa/scripts/check_wasm_e2e_coverage.py
  python3 qa/scripts/check_resource_coverage.py
  node qa/tests/randomness/nist/run.mjs
fi

command -v cargo >/dev/null 2>&1 || {
  echo 'ERROR: Cargo is required because run-all includes the full Rust and browser/WASM E2E gates.' >&2
  exit 1
}

if [[ "$resume_stage" == "full" ]]; then
  cargo check --all-targets --all-features
  cargo test --all-targets
  cargo test --doc
  cargo test --manifest-path qa/Cargo.toml --all-targets
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --manifest-path qa/benches/Cargo.toml --no-run
  cargo check --manifest-path qa/tests/fuzz/Cargo.toml
fi

if [[ "$resume_stage" == "full" || "$resume_stage" == "wasm" ]]; then
  command -v rustup >/dev/null 2>&1 || {
    echo 'ERROR: rustup is required because run-all includes the browser/WASM E2E gate.' >&2
    exit 1
  }
  echo '==> WASM compile QA'
  rustup target add wasm32-unknown-unknown
  cargo check --target wasm32-unknown-unknown --features wasm
fi

if [[ "$resume_stage" != "rust-e2e" && "$resume_stage" != "live-e2e" && "$resume_stage" != "funded-e2e" && "$resume_stage" != "browser-e2e" && "$resume_stage" != "resources-e2e" ]]; then
  echo '==> Formatting QA'
  if cargo fmt --version >/dev/null 2>&1; then
    cargo fmt --all -- --check
  fi
fi

source qa/scripts/load-e2e-networks.sh

if [[ "$resume_stage" != "resources-e2e" ]]; then
  source qa/scripts/prepare-e2e-funding.sh standard
  source qa/scripts/prepare-e2e-funding.sh covenant
fi

if [[ "$resume_stage" != "browser-e2e" && "$resume_stage" != "resources-e2e" ]]; then
  echo "==> Full Rust E2E"
  rust_e2e_args=()
  [[ "$resume_stage" == "live-e2e" ]] && rust_e2e_args+=(--from-live)
  [[ "$resume_stage" == "funded-e2e" ]] && rust_e2e_args+=(--from-funded)
  bash qa/scripts/run-e2e-rust.sh "${rust_e2e_args[@]}"
fi

if [[ "$resume_stage" != "resources-e2e" ]]; then
  echo "==> Full browser/WASM E2E"
  bash qa/scripts/run-e2e-browser.sh
fi

echo "==> Quick resource/fault E2E"
bash qa/scripts/run-e2e-resources.sh --quick

if [[ "${KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED:-0}" == "1" && "${KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED:-0}" == "1" ]]; then
  echo "ALL NON-FUNDED QA + E2E GATES: PASS"
  echo "NOTE: both funded network roles were skipped at user request or by network safety policy."
else
  echo "ALL SELECTED QA + E2E GATES: PASS"
  [[ "${KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED:-0}" == "1" ]] && echo "NOTE: funded standard-network scenarios on $KASPA_PORTAL_E2E_STANDARD_NETWORK were skipped."
  [[ "${KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED:-0}" == "1" ]] && echo "NOTE: funded covenant-network scenarios on $KASPA_PORTAL_E2E_COVENANT_NETWORK were skipped."
fi
