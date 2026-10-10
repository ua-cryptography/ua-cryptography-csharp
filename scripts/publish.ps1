<#
.SYNOPSIS
Builds ua-sign as one self-contained executable: artifacts/ua-sign/RID/ua-sign(.exe), picked up by scripts/ua-sign.ps1.

.EXAMPLE
scripts/publish.ps1
scripts/publish.ps1 -Rid linux-x64
#>
param([string] $Rid)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Rid) {
    $Rid = (& dotnet --info | Select-String '^\s*RID:\s*(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
}
& dotnet publish (Join-Path $root 'src/UA.Cryptography.Cli') -c Release -r $Rid --self-contained `
    -p:PublishSingleFile=true -p:DebugType=none -o (Join-Path $root "artifacts/ua-sign/$Rid")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "Published: $(Join-Path $root "artifacts/ua-sign/$Rid")"
