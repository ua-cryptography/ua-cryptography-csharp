<#
.SYNOPSIS
Verifies a signature (.p7s, .xml, .asics, .asice) and prints every check. Exit code: 0 valid, 1 invalid, 2 error.

.EXAMPLE
scripts/verify.ps1 contract.pdf.p7s
scripts/verify.ps1 contract.pdf.p7s -Data contract.pdf -Trust czo-root.cer
scripts/verify.ps1 contract.asice -Trust czo-root.cer -Online -Extract out
scripts/verify.ps1 contract.asice -Trust czo-root.cer -Report contract.report.ini

-Trust and -Certs accept several files; -Online asks OCSP responders and downloads missing CA certificates;
-Report also writes a detailed INI report in UTF-8 (algorithms, signer, digests, time-stamps, paths, OCSP, checks).
#>
param(
    [Parameter(Mandatory)] [string] $Signature,
    [string] $Data,
    [string[]] $Trust = @(),
    [string[]] $Certs = @(),
    [switch] $Online,
    [string] $Extract,
    [string] $Report,
    [Parameter(ValueFromRemainingArguments)] [string[]] $Rest = @()
)
$arguments = @('verify', '--in', $Signature)
if ($Data) { $arguments += @('--data', $Data) }
foreach ($t in $Trust) { $arguments += @('--trust', $t) }
foreach ($c in $Certs) { $arguments += @('--certs', $c) }
if ($Online) { $arguments += '--online' }
if ($Extract) { $arguments += @('--extract', $Extract) }
if ($Report) { $arguments += @('--report', $Report) }
& (Join-Path $PSScriptRoot 'ua-sign.ps1') @arguments @Rest
exit $LASTEXITCODE
