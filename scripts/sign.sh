#!/usr/bin/env bash
# Signs a file.
#
#   scripts/sign.sh FORMAT KEYSTORE FILE [LEVEL] [more ua-sign sign options...]
#
#   FORMAT    cades | cades-detached | xades | asic-s | asic-e
#   KEYSTORE  the .jks key store
#   FILE      the file to sign
#   LEVEL     B (default), T or LT; T and LT need --tsa URL unless the certificate names a time-stamping service,
#             LT also asks the OCSP responders named in the certificates (or --ocsp URL)
#
# Examples:
#   scripts/sign.sh cades key.jks contract.pdf
#   scripts/sign.sh asic-e key.jks contract.pdf T --tsa http://tsp.example/
#   scripts/sign.sh xades key.jks contract.pdf B --hash gost34311
#
# The result is FILE plus .p7s, .xml, .asics or .asice (or --out PATH).
# Password: the UA_SIGN_PASSWORD environment variable, otherwise it is asked.
set -euo pipefail

if [[ $# -lt 3 ]]; then
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
format="$1"; keystore="$2"; file="$3"; level="${4:-B}"
shift $(( $# < 4 ? $# : 4 ))

extra=()
if [[ "$format" == "cades-detached" ]]; then
  format="cades"; extra+=(--detached)
fi

exec "$(dirname "$0")/ua-sign.sh" sign --keystore "$keystore" --format "$format" --in "$file" --level "$level" \
  ${extra[@]+"${extra[@]}"} "$@"
