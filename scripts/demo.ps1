<#
.SYNOPSIS
End-to-end demonstration without network access: a key, a document signed in every format, every signature verified,
and a tampered copy rejected. Everything is written to artifacts/demo (git-ignored).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'artifacts/demo'
$uaSign = Join-Path $PSScriptRoot 'ua-sign.ps1'
if (-not $env:UA_SIGN_PASSWORD) { $env:UA_SIGN_PASSWORD = 'demo-password' }

Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dir | Out-Null
$document = Join-Path $dir 'document.txt'
[IO.File]::WriteAllText($document, "A document to sign / Документ для підпису`n")

& $uaSign keygen --keystore "$dir/demo.jks" --subject 'CN=Demo Signer,O=UA Cryptography Demo,C=UA' --cert "$dir/demo.cer"
foreach ($format in 'cades', 'xades', 'asic-s', 'asic-e') {
    & $uaSign sign --keystore "$dir/demo.jks" --format $format --in $document | Out-Null
}
& $uaSign sign --keystore "$dir/demo.jks" --format cades --detached --hash gost34311 --in $document --out "$dir/document.detached.p7s" | Out-Null

$status = 0
foreach ($signed in 'document.txt.p7s', 'document.txt.xml', 'document.txt.asics', 'document.txt.asice', 'document.detached.p7s') {
    $extra = @()
    if ($signed -eq 'document.detached.p7s') { $extra = @('--data', $document) }
    & $uaSign verify --in "$dir/$signed" @extra --trust "$dir/demo.cer" --quiet > "$dir/$signed.report.txt"
    if ($LASTEXITCODE -eq 0) { Write-Output "valid:    $signed" } else { Write-Output "INVALID:  $signed"; $status = 1 }
}

$bytes = [IO.File]::ReadAllBytes("$dir/document.txt.p7s")
$marker = [Text.Encoding]::ASCII.GetBytes('A document')
for ($i = 0; $i -le $bytes.Length - $marker.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $marker.Length; $j++) { if ($bytes[$i + $j] -ne $marker[$j]) { $match = $false; break } }
    if ($match) { $bytes[$i] = [byte][char]'x'; break }
}
[IO.File]::WriteAllBytes("$dir/tampered.p7s", $bytes)
& $uaSign verify --in "$dir/tampered.p7s" --quiet > "$dir/tampered.report.txt"
if ($LASTEXITCODE -eq 1) { Write-Output 'rejected: tampered.p7s (as expected)' } else { Write-Output 'UNEXPECTED: the tampered signature verifies'; $status = 1 }
exit $status
