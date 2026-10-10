<#
.SYNOPSIS
Creates a JKS key store with a new DSTU 4145 key and a self-signed certificate (KEYSTORE.cer next to it).

.EXAMPLE
scripts/keygen.ps1 key.jks "CN=Name,O=Organization,C=UA"
scripts/keygen.ps1 key.jks "CN=Name,O=Organization,C=UA" -Curve 431 -Days 730

The password comes from the UA_SIGN_PASSWORD environment variable, otherwise it is asked twice.
#>
param(
    [Parameter(Mandatory)] [string] $Keystore,
    [Parameter(Mandatory)] [string] $Subject,
    [ValidateSet(163, 167, 173, 179, 191, 233, 257, 307, 367, 431)] [int] $Curve = 257,
    [int] $Days = 365,
    [Parameter(ValueFromRemainingArguments)] [string[]] $Rest = @()
)
& (Join-Path $PSScriptRoot 'ua-sign.ps1') keygen --keystore $Keystore --subject $Subject --curve $Curve --days $Days --cert "$Keystore.cer" @Rest
exit $LASTEXITCODE
