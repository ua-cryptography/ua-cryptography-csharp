#!/usr/bin/env bash
# Runs ua-sign with all arguments passed through.
# Uses the binary built by scripts/publish.sh when it exists, otherwise builds and runs the project with dotnet.
# If UA_SIGN_PASSWORD is set, the key store password is taken from it (--password-env UA_SIGN_PASSWORD).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${UA_SIGN:-}"
if [[ -z "$binary" ]]; then
  for candidate in "$root"/artifacts/ua-sign/*/ua-sign; do
    if [[ -x "$candidate" ]]; then binary="$candidate"; break; fi
  done
fi

args=("$@")
if [[ -n "${UA_SIGN_PASSWORD:-}" && $# -gt 0 && "$1" =~ ^(keygen|info|sign)$ ]]; then
  has_password=false
  for a in "$@"; do
    [[ "$a" == --password* ]] && has_password=true
  done
  $has_password || args+=(--password-env UA_SIGN_PASSWORD)
fi

if [[ -n "$binary" ]]; then
  exec "$binary" "${args[@]}"
else
  exec dotnet run --project "$root/src/UA.Cryptography.Cli" -c Release -v quiet -- "${args[@]}"
fi
