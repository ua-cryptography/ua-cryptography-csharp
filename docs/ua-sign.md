# ua-sign — signing and verification from the command line

`ua-sign` (`src/UA.Cryptography.Cli`) signs and verifies files in the formats of the Ukrainian PKI with DSTU 4145 keys
kept in JKS key stores. It is built on [UA.Cryptography.Pki](#the-library-underneath) and uses no third-party
packages.

| Command | What it does |
|---|---|
| `keygen` | creates a JKS key store with a new DSTU 4145 key and a self-signed certificate |
| `info` | lists the entries of a key store, or shows certificates (DER, PEM, `.p7b`) |
| `sign` | signs files: CAdES, XAdES, ASiC-S, ASiC-E at levels B, T and LT |
| `verify` | verifies a signature of any of these formats and prints every check |

Exit codes: **0** — done / the signature is valid, **1** — the signature is invalid, **2** — a usage or processing
error (wrong password, unreadable file, network failure). `ua-sign <command> --help` lists the options of a command.

## Running it

```bash
scripts/publish.sh                      # one self-contained executable: artifacts/ua-sign/<rid>/ua-sign
scripts/ua-sign.sh verify --in doc.p7s  # runs that executable, or `dotnet run` when it has not been published
scripts/demo.sh                         # key, every format, verification, a tampered copy rejected (offline)
```

On Windows the same scripts exist as `.ps1` (`scripts/publish.ps1`, `scripts/ua-sign.ps1`, …). The wrappers
`keygen`, `sign` and `verify` take the usual parameters positionally and pass any further `ua-sign` options through:

```bash
export UA_SIGN_PASSWORD='…'                                     # or leave it unset to be asked
scripts/keygen.sh key.jks "CN=Name,O=Organization,C=UA" 257 365
scripts/sign.sh cades key.jks contract.pdf                       # contract.pdf.p7s, data inside
scripts/sign.sh cades-detached key.jks contract.pdf T --tsa http://tsp.example/
scripts/sign.sh asic-e key.jks contract.pdf LT
scripts/verify.sh contract.pdf.p7s --trust czo-root-2036-dstu7564.cer
```

```powershell
$env:UA_SIGN_PASSWORD = '…'
scripts/keygen.ps1 key.jks "CN=Name,O=Organization,C=UA" -Curve 257
scripts/sign.ps1 xades key.jks contract.pdf -Hash gost34311
scripts/verify.ps1 contract.pdf.xml -Trust czo-root.cer -Online
```

## Passwords

The key store password is read from `--password-env NAME` (an environment variable), `--password-file PATH` (the
first line) or typed at the terminal without echo. `--password VALUE` exists for tests and private machines: other
processes can see command lines. The key entry is expected to have the same password as the store, as in the stores
issued by Ukrainian banks.

## keygen

```bash
ua-sign keygen --keystore key.jks --subject "CN=Name,O=Organization,C=UA" [--alias key] [--curve 257] [--days 365]
               [--signature-hash dstu7564|gost34311] [--cert key.cer] [--force]
```

The key lies on a curve of table Г.1 (polynomial basis, the default m = 257 as in the national PKI) with DKE No. 1
written into the parameters. The certificate is self-signed (basicConstraints cA = false, keyUsage digitalSignature
and nonRepudiation, a subject key identifier) and signed with DSTU 4145 + DSTU 7564 unless `--signature-hash gost34311`
is given. Signatures made with such a key verify, with the certificate given as `--trust`, but they are not qualified:
a qualified certificate is issued by a qualified trust service provider (КНЕДП).

## sign

```bash
ua-sign sign --keystore key.jks --format cades|xades|asic-s|asic-e --in FILE [--in FILE…] [--out PATH]
             [--level B|T|LT] [--hash dstu7564|gost34311] [--detached] [--content-timestamp]
             [--tsa URL] [--ocsp URL] [--certs CA.cer…] [--alias NAME] [--force]
```

| Format | Result | Contents |
|---|---|---|
| `cades` | `FILE.p7s` | CMS SignedData with the data (`--detached`: without it) |
| `xades` | `FILE.xml` | a detached `ds:Signature` with one reference per file; the files stay next to it |
| `asic-s` | `FILE.asics` | ZIP: `mimetype`, the file, `META-INF/signature.p7s` (detached CAdES) |
| `asic-e` | `FILE.asice` | ZIP: `mimetype`, the files, `META-INF/manifest.xml`, `META-INF/signatures001.xml` (XAdES) |

| Level | CAdES | XAdES | Needs |
|---|---|---|---|
| `B` | signed attributes | signed properties | — |
| `T` | + signatureTimeStampToken | + SignatureTimeStamp | a time-stamping service |
| `LT` | CAdES-X Long: + references and values of the CA certificates and OCSP responses | XAdES-B-LT: + CertificateValues, RevocationValues | the TSA and the OCSP responders |

The time-stamping service is `--tsa URL`, or the one the signer's certificate names (subjectInfoAccess,
id-ad-timeStamping) — Ukrainian qualified certificates do. For LT the responders come from each certificate's
authorityInfoAccess (or `--ocsp URL` for all), and missing CA certificates are downloaded from caIssuers or taken from
`--certs`. A self-signed key has nothing to ask OCSP about, so LT only adds the time-stamp to it.

The formats follow [signature-formats.md](signature-formats.md): signature algorithm DSTU 4145 + DSTU 7564-256
(`--hash dstu7564`, default) or DSTU 4145 + GOST 34.311 (`--hash gost34311`; GOST hashing uses the DKE of the key),
the hash reversed before 5.9, D stored little-endian, exclusive canonicalization in XAdES.

## verify

```bash
ua-sign verify --in SIGNATURE [--data FILE…] [--trust ROOT…] [--certs CA…] [--online] [--extract DIR] [--quiet]
```

The format is recognised by the content: a ZIP is ASiC-S / ASiC-E, XML is XAdES, anything else is CAdES (DER, PEM or
base64). The data of a detached signature is `--data`, or the file next to the signature with the name the signature
uses (`doc.txt` for `doc.txt.p7s`, the reference URIs in XAdES).

Every signature is reported check by check — `[ OK ]`, `[WARN]`, `[FAIL]`:

- the binding to the data (messageDigest, ds:Reference digests) and to the certificate (signingCertificateV2,
  SigningCertificateV2), the DSTU 4145 signature;
- time-stamps: the imprint, the service's signature and certificate path; the time-stamp time becomes the validation
  time;
- CAdES-X Long references against their values;
- the certificate path: each signature, the validity periods at the validation time, CA flags, the trust anchor
  (`--trust`; without it the root is reported with a warning), and an OCSP response for every certificate below the
  root — embedded in the signature, or asked online with `--online`;
- for containers: the mimetype entry, the manifest, and that every data file is covered by a signature.

A signature is valid when no check failed; warnings mark what could not be established (no trusted root given, no
revocation data). Trusted roots for qualified signatures are the ЦЗО certificates
(`tests/UA.Cryptography.Tests/TestData/certificates/czo-roots` holds the current ones).

## What is not supported

- PAdES (PDF signatures) — neither signing nor verification.
- Key containers other than Sun JKS: PKCS#12, JCEKS, IIT `Key-6.dat` / `.ZS2`.
- CRLs, XAdES-B-LTA / CAdES-A archive time-stamps, countersignatures, CAdES inside ASiC-E (ASiCManifest).
- Certificate policies and qcStatements are not evaluated; the freshness of an OCSP response relative to the signing
  time and the OCSP nonce are not checked.

## The library underneath

`UA.Cryptography.Pki` (`src/UA.Cryptography.Pki`, .NET 8, depends only on `UA.Cryptography` and the base class
library) can be used without the tool:

```csharp
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

JksKeyStore store = JksKeyStore.Load(File.ReadAllBytes("key.jks"), password);
SigningKey signer = SigningKey.FromJks(store, password);
byte[] p7s = new CadesSigner(signer).Sign(data, new CadesOptions(Oids.Dstu7564_256, Detached: true));

VerificationResult result = SignatureVerifier.Verify(p7s, _ => data,
    new ValidationOptions { TrustAnchors = [Certificate.Load("czo-root.cer")] });
```

| Namespace | Contents |
|---|---|
| `Asn1` | DER/BER reader (`Asn1Node`), DER writer (`Der`), PEM |
| `X509` | certificates, distinguished names, DSTU 4145 public and private keys (SPKI, PKCS#8), `CertificateBuilder` |
| `KeyStore` | Sun JKS: several entries, the Sun key protector, modified UTF-8 aliases |
| `Cms`, `Cades` | SignedData, SignerInfo, signed attributes; CAdES signer and verifier |
| `Tsp`, `Ocsp`, `Services` | RFC 3161 tokens and protocol, OCSP responses and requests, HTTP clients |
| `Xml`, `Xades`, `Asic` | inclusive and exclusive C14N, XAdES signer and verifier, ASiC containers |
| `Validation` | certification path validation, verification reports |
