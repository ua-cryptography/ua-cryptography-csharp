<#
.SYNOPSIS
Signs a file: CAdES (.p7s, enveloped or detached), XAdES (.xml), ASiC-S (.asics) or ASiC-E (.asice).

.EXAMPLE
scripts/sign.ps1 cades key.jks contract.pdf
scripts/sign.ps1 cades-detached key.jks contract.pdf -Hash gost34311
scripts/sign.ps1 asic-e key.jks contract.pdf -Level T -Tsa http://tsp.example/

Levels T and LT need a time-stamping service (-Tsa, unless the certificate names one); LT also asks the OCSP
responders named in the certificates (or -Ocsp). Any other ua-sign sign option can follow, e.g. --out PATH.
The password comes from the UA_SIGN_PASSWORD environment variable, otherwise it is asked.
#>
param(
    [Parameter(Mandatory)] [ValidateSet('cades', 'cades-detached', 'xades', 'asic-s', 'asic-e')] [string] $Format,
    [Parameter(Mandatory)] [string] $Keystore,
    [Parameter(Mandatory)] [string] $File,
    [ValidateSet('B', 'T', 'LT')] [string] $Level = 'B',
    [ValidateSet('dstu7564', 'gost34311')] [string] $Hash = 'dstu7564',
    [string] $Tsa,
    [string] $Ocsp,
    [Parameter(ValueFromRemainingArguments)] [string[]] $Rest = @()
)
$arguments = @('sign', '--keystore', $Keystore, '--in', $File, '--level', $Level, '--hash', $Hash)
if ($Format -eq 'cades-detached') { $arguments += @('--format', 'cades', '--detached') } else { $arguments += @('--format', $Format) }
if ($Tsa) { $arguments += @('--tsa', $Tsa) }
if ($Ocsp) { $arguments += @('--ocsp', $Ocsp) }
& (Join-Path $PSScriptRoot 'ua-sign.ps1') @arguments @Rest
exit $LASTEXITCODE
