#!/usr/bin/env bash
# Builds ua-sign as one self-contained executable for this machine (or for RID, e.g. linux-x64, win-x64, osx-arm64):
#
#   scripts/publish.sh [RID]
#
# The result is artifacts/ua-sign/RID/ua-sign; scripts/ua-sign.sh picks it up automatically.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rid="${1:-$(dotnet --info | awk '/^ *RID:/ { print $2; exit }')}"
dotnet publish "$root/src/UA.Cryptography.Cli" -c Release -r "$rid" --self-contained \
  -p:PublishSingleFile=true -p:DebugType=none -o "$root/artifacts/ua-sign/$rid"
echo "Published: $root/artifacts/ua-sign/$rid"
