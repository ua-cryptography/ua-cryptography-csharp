#!/usr/bin/env bash
# Verifies a signature (.p7s, .xml, .asics, .asice) and prints every check.
#
#   scripts/verify.sh SIGNATURE [DATA] [more ua-sign verify options...]
#
#   SIGNATURE  the signed file
#   DATA       the signed file of a detached signature (default: found next to the signature by name)
#
# Useful options:
#   --trust ROOT.cer   trusted root certificates (for example the ЦЗО roots); repeatable
#   --certs CA.cer     CA certificates that complete the chain; repeatable
#   --online           ask OCSP responders and download missing CA certificates
#   --extract DIR      write the signed content into DIR
#
# Exit code: 0 valid, 1 invalid, 2 error.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
signature="$1"; shift
data=()
if [[ $# -gt 0 && "$1" != --* ]]; then
  data=(--data "$1"); shift
fi

exec "$(dirname "$0")/ua-sign.sh" verify --in "$signature" ${data[@]+"${data[@]}"} "$@"
