# Runs ua-sign with all arguments passed through (Windows PowerShell 5.1 and PowerShell 7).
# Uses the binary built by scripts/publish.ps1 when it exists, otherwise builds and runs the project with dotnet.
# If UA_SIGN_PASSWORD is set, the key store password is taken from it (--password-env UA_SIGN_PASSWORD).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$binary = $env:UA_SIGN
if (-not $binary) {
    $binary = Get-ChildItem -Path (Join-Path $root 'artifacts/ua-sign') -Recurse -Include 'ua-sign.exe', 'ua-sign' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}

$arguments = @($args)
if ($env:UA_SIGN_PASSWORD -and $arguments.Count -gt 0 -and $arguments[0] -in 'keygen', 'info', 'sign' -and
    -not ($arguments | Where-Object { "$_" -like '--password*' })) {
    $arguments += @('--password-env', 'UA_SIGN_PASSWORD')
}

if ($binary) {
    & $binary @arguments
} else {
    & dotnet run --project (Join-Path $root 'src/UA.Cryptography.Cli') -c Release -v quiet -- @arguments
}
exit $LASTEXITCODE
