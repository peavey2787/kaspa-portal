#!/usr/bin/env bash
# Source/call convention: this script is sourced by the runners with role standard|covenant.
role="${1:?usage: source qa/scripts/prepare-e2e-funding.sh standard|covenant}"
case "$role" in standard|covenant) ;; *) echo "ERROR: funding role must be standard or covenant" >&2; return 2 ;; esac
upper="${role^^}"
network_var="KASPA_PORTAL_E2E_${upper}_NETWORK"
endpoint_var="KASPA_PORTAL_E2E_${upper}_ENDPOINT"
rest_endpoint_var="KASPA_PORTAL_E2E_${upper}_REST_ENDPOINT"
faucet_var="KASPA_PORTAL_E2E_${upper}_FAUCET"
supported_var="KASPA_PORTAL_E2E_${upper}_FUNDED_SUPPORTED"
verified_var="KASPA_PORTAL_E2E_${upper}_FUNDED_VERIFIED"
skip_var="KASPA_PORTAL_E2E_SKIP_${upper}_FUNDED"
network="${!network_var}"
endpoint="${!endpoint_var}"
rest_endpoint="${!rest_endpoint_var:-}"
faucet="${!faucet_var:-}"
supported="${!supported_var:-0}"

if [[ "$network" == "mainnet" ]]; then
  if [[ "${KASPA_PORTAL_E2E_ALLOW_MAINNET_SPEND:-0}" == "1" ]]; then
    supported=1
  else
    supported=0
  fi
fi
if [[ "$supported" != "1" ]]; then
  export "$skip_var=1"
  echo "Funded $role-network spending is disabled for $network; read-only coverage will continue."
  unset role upper network_var endpoint_var rest_endpoint_var faucet_var supported_var verified_var skip_var network endpoint rest_endpoint faucet supported
  return 0
fi
if [[ "${!verified_var:-0}" == "1" ]]; then
  unset role upper network_var endpoint_var rest_endpoint_var faucet_var supported_var verified_var skip_var network endpoint rest_endpoint faucet supported
  return 0
fi
if [[ "${!skip_var:-0}" == "1" ]]; then
  unset role upper network_var endpoint_var rest_endpoint_var faucet_var supported_var verified_var skip_var network endpoint rest_endpoint faucet supported
  return 0
fi

state_file="$ROOT/.kaspa-portal-e2e/wallet.env"
wallet_args=(--state-file "$state_file" --network "$network" --endpoint "$endpoint" --rest-endpoint "$rest_endpoint" --faucet "$faucet")
cargo run --quiet --manifest-path qa/Cargo.toml --bin e2e_wallet -- "${wallet_args[@]}"
while true; do
  printf '\nHave you funded the %s E2E wallet with at least 10 KAS? [Y/N] ' "$network"
  if ! IFS= read -r answer; then
    echo "ERROR: Could not read Y/N funding choice." >&2
    return 1
  fi
  case "$answer" in
    [Yy])
      set +e
      cargo run --quiet --manifest-path qa/Cargo.toml --bin e2e_wallet -- "${wallet_args[@]}" --check-funded
      rc=$?
      set -e
      if [[ "$rc" -eq 0 ]]; then
        if [[ -z "${KASPA_PORTAL_E2E_XPRV:-}" ]]; then
          xprv_line="$(grep -m1 '^KASPA_PORTAL_E2E_XPRV=' "$state_file" || true)"
          if [[ -z "$xprv_line" ]]; then
            echo "ERROR: generated E2E wallet state does not contain KASPA_PORTAL_E2E_XPRV." >&2
            return 1
          fi
          export KASPA_PORTAL_E2E_XPRV="${xprv_line#KASPA_PORTAL_E2E_XPRV=}"
        fi
        export "$verified_var=1"
        unset "$skip_var" || true
        break
      elif [[ "$rc" -eq 10 ]]; then
        echo "The wallet still needs at least 10 KAS on $network. Fund the address shown above, then press Y; press N to skip only this network's funded tests."
      else
        return "$rc"
      fi
      ;;
    [Nn])
      export "$skip_var=1"
      echo "Funded $role-network tests on $network will be skipped; the remaining E2E tests will continue."
      break
      ;;
    *) echo "Please enter Y or N." ;;
  esac
done
unset role upper network_var endpoint_var rest_endpoint_var faucet_var supported_var verified_var skip_var network endpoint rest_endpoint faucet supported state_file wallet_args answer rc xprv_line
