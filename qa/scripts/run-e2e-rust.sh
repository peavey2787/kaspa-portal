#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MODE="full"
START_STAGE="offline"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --read-only) MODE="read-only" ;;
    --from-live) START_STAGE="live" ;;
    --from-funded) START_STAGE="funded" ;;
    *) echo "Usage: qa/scripts/run-e2e-rust.sh [--from-live] [--from-funded] [--read-only]" >&2; exit 2 ;;
  esac
  shift
done

source qa/scripts/load-e2e-networks.sh
python3 qa/scripts/check_capability_parity.py
python3 qa/scripts/check_rust_e2e_coverage.py
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

if [[ "$MODE" == "read-only" ]]; then
  export KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED=1
  export KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED=1
else
  source qa/scripts/prepare-e2e-funding.sh standard
  source qa/scripts/prepare-e2e-funding.sh covenant
fi

if [[ "$START_STAGE" == "offline" ]]; then
  echo "==> Rust E2E: offline facade workflows (standard=$KASPA_PORTAL_E2E_STANDARD_NETWORK, covenant=$KASPA_PORTAL_E2E_COVENANT_NETWORK)"
  cargo test --manifest-path qa/Cargo.toml --test e2e-rust-offline -- --ignored --nocapture --test-threads=1
fi

if [[ "$START_STAGE" != "funded" ]]; then
  echo "==> Rust E2E: public $KASPA_PORTAL_E2E_STANDARD_NETWORK read-only workflows"
  cargo test --manifest-path qa/Cargo.toml --test e2e-rust-live-network -- --ignored --nocapture --test-threads=1
fi

if [[ "${KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED:-0}" == "1" ]]; then
  echo "NOTE: funded standard-network workflows on $KASPA_PORTAL_E2E_STANDARD_NETWORK were skipped."
else
  echo "==> Rust E2E: funded ordinary workflows on $KASPA_PORTAL_E2E_STANDARD_NETWORK"
  cargo test --manifest-path qa/Cargo.toml --test e2e-rust-funded-networks rust_funded_standard_network_transactions -- --ignored --nocapture --test-threads=1
fi

if [[ "${KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED:-0}" == "1" ]]; then
  echo "NOTE: funded covenant workflows on $KASPA_PORTAL_E2E_COVENANT_NETWORK were skipped."
else
  echo "==> Rust E2E: funded covenant workflows on $KASPA_PORTAL_E2E_COVENANT_NETWORK"
  cargo test --manifest-path qa/Cargo.toml --test e2e-rust-funded-networks rust_funded_covenant_network_transactions -- --ignored --nocapture --test-threads=1
fi

echo "ALL SELECTED RUST E2E GATES: PASS"
