#!/usr/bin/env bash
# Source this file from QA runners. It exports the selected standard/covenant networks.
if [[ "${KASPA_PORTAL_E2E_NETWORKS_RESOLVED:-0}" != "1" ]]; then
  _kaspa_network_assignments="$(python3 qa/scripts/select_e2e_network.py --prompt)" || return $?
  while IFS='=' read -r _kaspa_key _kaspa_value; do
    [[ -z "$_kaspa_key" ]] && continue
    export "$_kaspa_key=$_kaspa_value"
  done <<<"$_kaspa_network_assignments"
  unset _kaspa_network_assignments _kaspa_key _kaspa_value
fi
