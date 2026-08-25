#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

bash qa/scripts/run-all.sh "$@"
rc=$?
printf '\n'
if [ "$rc" -eq 0 ]; then
  printf 'Kaspa Portal QA finished successfully.\n'
else
  printf 'Kaspa Portal QA FAILED with exit code %s.\n' "$rc"
fi

# Keep a terminal opened by a graphical file manager visible long enough to read.
if [ -t 0 ] && [ -t 1 ]; then
  printf '\nPress Enter to close...'
  read -r _
fi
exit "$rc"
