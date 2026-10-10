#!/usr/bin/env bash
# Creates a JKS key store with a new DSTU 4145 key and a self-signed certificate.
#
#   scripts/keygen.sh KEYSTORE SUBJECT [CURVE] [DAYS] [more ua-sign keygen options...]
#
#   KEYSTORE  the .jks file to create
#   SUBJECT   e.g. "CN=Name,O=Organization,C=UA"
#   CURVE     degree m of a curve of table Г.1: 163 167 173 179 191 233 257 307 367 431 (default 257)
#   DAYS      certificate validity (default 365)
#
# The certificate is also written next to the key store as KEYSTORE.cer.
# Password: the UA_SIGN_PASSWORD environment variable, otherwise it is asked twice.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
keystore="$1"; subject="$2"; curve="${3:-257}"; days="${4:-365}"
shift $(( $# < 4 ? $# : 4 ))

exec "$(dirname "$0")/ua-sign.sh" keygen --keystore "$keystore" --subject "$subject" --curve "$curve" --days "$days" \
  --cert "$keystore.cer" "$@"
