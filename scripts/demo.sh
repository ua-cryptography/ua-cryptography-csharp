#!/usr/bin/env bash
# End-to-end demonstration without network access: a key, a document signed in every format, every signature
# verified, and a tampered copy rejected. Everything is written to artifacts/demo (git-ignored).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$root/artifacts/demo"
ua_sign="$root/scripts/ua-sign.sh"
export UA_SIGN_PASSWORD="${UA_SIGN_PASSWORD:-demo-password}"

rm -rf "$dir" && mkdir -p "$dir"
echo "A document to sign / Документ для підпису" > "$dir/document.txt"

"$ua_sign" keygen --keystore "$dir/demo.jks" --subject "CN=Demo Signer,O=UA Cryptography Demo,C=UA" --cert "$dir/demo.cer"

for format in cades xades asic-s asic-e; do
  "$ua_sign" sign --keystore "$dir/demo.jks" --format "$format" --in "$dir/document.txt" > /dev/null
done
"$ua_sign" sign --keystore "$dir/demo.jks" --format cades --detached --hash gost34311 \
  --in "$dir/document.txt" --out "$dir/document.detached.p7s" > /dev/null

status=0
for signed in document.txt.p7s document.txt.xml document.txt.asics document.txt.asice document.detached.p7s; do
  data=()
  [[ "$signed" == document.detached.p7s ]] && data=(--data "$dir/document.txt")
  if "$ua_sign" verify --in "$dir/$signed" ${data[@]+"${data[@]}"} --trust "$dir/demo.cer" --quiet > "$dir/$signed.report.txt"; then
    echo "valid:    $signed"
  else
    echo "INVALID:  $signed (see $signed.report.txt)"; status=1
  fi
done

cp "$dir/document.txt.p7s" "$dir/tampered.p7s"
printf 'x' | dd of="$dir/tampered.p7s" bs=1 seek=$(( $(grep -abo 'A document' "$dir/tampered.p7s" | head -1 | cut -d: -f1) )) conv=notrunc 2> /dev/null
if "$ua_sign" verify --in "$dir/tampered.p7s" --quiet > "$dir/tampered.report.txt"; then
  echo "UNEXPECTED: the tampered signature verifies"; status=1
else
  echo "rejected: tampered.p7s (as expected)"
fi
exit $status
