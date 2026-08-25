#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

bash qa/scripts/run-e2e-rust.sh "$@"
rc=$?
printf '\n'
if [ "$rc" -eq 0 ]; then
  printf 'Kaspa Portal Rust E2E finished successfully.\n'
else
  printf 'Kaspa Portal Rust E2E FAILED with exit code %s.\n' "$rc"
fi

if [ -t 0 ] && [ -t 1 ]; then
  printf '\nPress Enter to close...'
  read -r _
fi
exit "$rc"
