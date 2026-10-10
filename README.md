# UA.Cryptography

[![CI](https://github.com/ua-cryptography/ua-cryptography-csharp/actions/workflows/ci.yml/badge.svg)](https://github.com/ua-cryptography/ua-cryptography-csharp/actions/workflows/ci.yml)

Ukrainian cryptographic standards for .NET, with no external dependencies:

- **DSTU 4145-2002** — elliptic-curve digital signature over GF(2^m) in both bases, **polynomial (PB)** and **optimal
  normal (ONB)**, with all recommended curves and the random bit generator of Appendix А;
- **GOST 34.311-95** (with any S-box table / DKE) and **GOST 28147-89**;
- **DSTU 7564:2014 "Kupyna"** — 256/384/512-bit hash;
- **DSTU 7624:2014 "Kalyna"** — 128/256/512-bit block cipher and the ECB, CBC, CFB, OFB, CTR, CMAC, CCM, GCM, GMAC,
  XTS and KW modes.

Signatures are compatible with the Ukrainian PKI: the tests check real certificates of the Central Certification
Authority (ЦЗО) and of qualified CAs (ЦСК), and XAdES, CAdES, ASiC and PAdES signatures at every level (timestamps,
OCSP, DSS) are built by a synthetic PKI of the same shape and verified by the library code.

On top of it, also without third-party dependencies:

- **UA.Cryptography.Pki** — DER, X.509 with DSTU 4145 keys, JKS key stores, CMS/CAdES (B, T, X Long), RFC 3161
  timestamps, OCSP, inclusive and exclusive XML canonicalization, XAdES (B, T, LT), ASiC-S and ASiC-E, certification
  path validation;
- **ua-sign** — a command-line tool that creates keys in JKS, signs files in all these formats and verifies them
  ([docs/ua-sign.md](docs/ua-sign.md)), with launch scripts in `scripts/`.

The appendices and clauses of DSTU 4145-2002 are cited by their original Cyrillic designators: Appendix А, Б, В, Г
(the first to the fourth appendix), clauses Б.1, В.8, tables Г.1, Г.2 and so on. The text of the standard is not
included in the repository: it is copyrighted by Derzhstandart of Ukraine and may not be redistributed.

## Quick start

```csharp
using UA.Cryptography.Dstu4145;

var parameters = Dstu4145NamedCurves.Polynomial(257);       // or Dstu4145NamedCurves.OptimalNormal(173)
var signer = new Dstu4145Signer(parameters);

Dstu4145KeyPair key = signer.GenerateKeyPair();              // d and Q = −dP (clause 9)
byte[] message = "Hello"u8.ToArray();

byte[] signature = signer.SignMessage(key.PrivateKey, message);    // GOST 34.311 + clause 12, D = S‖R (5.10)
bool ok = signer.VerifyMessage(key.PublicKey, message, signature); // clause 13
```

If the hash is computed by another function, use `SignHash`/`VerifyHash`. The hash is passed as the binary string
(h_{L_H−1}, …, h_0), most significant byte first, as in Appendix Б. The Ukrainian PKI reverses the bytes of the hash and
stores the signature in little-endian ([docs/signature-formats.md](docs/signature-formats.md), section 1):

```csharp
using UA.Cryptography.Dstu7564;

byte[] h = Dstu7564Hash.HashData(message);                   // Kupyna, 256 bits
Array.Reverse(h);                                            // as qualified signature tools sign it
byte[] d = signer.SignHash(key.PrivateKey, h);
Array.Reverse(d);                                            // how D is stored in certificates, CMS and XML
```

Authenticated encryption with Kalyna:

```csharp
using UA.Cryptography.Dstu7624;

var gcm = new Dstu7624Gcm(blockBits: 256, key: key256);
byte[] sealedData = gcm.Encrypt(nonce, associatedData, plainText, macBits: 256);
byte[] opened = gcm.Decrypt(nonce, associatedData, sealedData, macBits: 256); // CryptographicException if the tag does not match
```

## Where things are

| Standard | Clause | Code (`src/UA.Cryptography/`) |
|---|---|---|
| DSTU 4145 | 5.1–5.11 data representation, signature encoding | `Dstu4145/Dstu4145Encoding.cs` |
| | 5.2, table 1 — field in the polynomial basis | `Math/PolynomialBasisField.cs` |
| | В.2, В.4, table 2 — optimal normal basis of type 2 | `Math/OptimalNormalBasisField.cs` |
| | 6.4–6.7 trace, half-trace, quadratic equation; В.4 inversion (Itoh–Tsujii) | `Math/BinaryField.cs` |
| | В.6 — conversion between PB and ONB | `Math/BasisConverter.cs` |
| | 6.8–6.10 random point, point compression; В.8 addition, Montgomery ladder | `EC/BinaryCurve.cs` |
| | 6.11–6.13, 7.3, 8, 10 checks of parameters and keys, base point | `Dstu4145/Dstu4145DomainParameters.cs` |
| | 9, 11–13 keys, presignature, signature, verification | `Dstu4145/Dstu4145Signer.cs` |
| | Appendix А — random sequence generator | `Dstu4145/Dstu4145RandomGenerator.cs` |
| | Appendix Г — recommended curves (Г.1, Г.2) with base points | `Dstu4145/Dstu4145NamedCurves.cs` |
| GOST 34.311-95, GOST 28147-89 | hash (6.2 of DSTU 4145) and block cipher | `Gost/` |
| DSTU 7564:2014 | Kupyna | `Dstu7564/Dstu7564Hash.cs` |
| DSTU 7624:2014 | Kalyna, one file per mode | `Dstu7624/` |

The PKI layer (`src/UA.Cryptography.Pki/`, [docs/signature-formats.md](docs/signature-formats.md)):

| Format | Standard | Code (`src/UA.Cryptography.Pki/`) |
|---|---|---|
| DER / BER | X.690 | `Asn1/` |
| Certificates, DSTU 4145 keys (SPKI, PKCS#8) | RFC 5280, RFC 5208 | `X509/` |
| JKS key store | Sun JKS, the Sun key protector | `KeyStore/` |
| CMS, CAdES | RFC 5652, ETSI EN 319 122 | `Cms/`, `Cades/` |
| Timestamps, OCSP, HTTP clients | RFC 3161, RFC 6960 | `Tsp/`, `Ocsp/`, `Services/` |
| Canonical XML, XAdES | W3C C14N 1.0, Exclusive C14N 1.0, ETSI EN 319 132 | `Xml/`, `Xades/` |
| ASiC-S, ASiC-E | ETSI EN 319 162 | `Asic/` |
| Certification paths | RFC 5280, section 6 (subset) | `Validation/` |

## Build and test

Requires the .NET 10 SDK (the libraries target .NET 8; the tests, the benchmark and ua-sign target .NET 10).

```bash
dotnet build
dotnet test                                                        # 837 tests, a few seconds
dotnet run -c Release --project bench/UA.Cryptography.Benchmarks             # benchmark
dotnet run -c Release --project bench/UA.Cryptography.Benchmarks -- --portable # without PMULL/PCLMUL
```

What the tests check (`tests/UA.Cryptography.Tests`, folders mirror the library namespaces):

- **Worked examples of Appendix Б** — Б.1 (PB, m = 163) and Б.2 (ONB, m = 173): every intermediate value
  (Q, h, eP, y, r, s, D) matches the standard bit for bit.
- **Cross-check with BouncyCastle** (PB): all 10 curves of Г.1 with base points; point multiplication; signatures in
  both directions. **ONB** — against an independent reference implementation of ANSI X9.62 / IEEE 1363 multiplication
  and through basis conversion: kP in PB, converted to ONB, equals kP in ONB; the curves of Г.2 are the curves of Г.1
  in the normal basis.
- Field axioms for all 60 degrees of table 1 and all 14 degrees of table 2, irreducibility of the polynomials, the
  checks of clause 8 for all 15 recommended curves, edge cases of point multiplication, point compression.
- **GOST 28147/34.311** against BouncyCastle with four S-box tables and the published GOST R 34.11-94 vectors;
  **DSTU 7564** — 17 test examples and a cross-check with BouncyCastle; **DSTU 7624** — the examples of the standard
  and 590 vectors from BouncyCastle Java 1.86 (`tools/dstu7624-vectors`).
- **Real certificates** (public, `TestData/certificates`): the ЦЗО roots (GOST 34.311 and DSTU 7564), the "Дія" CA →
  the ЦЗО root, five CA certificates from 2005–2015 (m = 257 and 431, three different DKEs).
- **Signature formats** on a synthetic PKI of the same shape as the national one (root m = 431 → CA → signer, TSA,
  OCSP): XAdES-B-B/T/LT as a separate file and inside ASiC-E, CAdES-B/T/X Long enveloped and detached, ASiC-S,
  PAdES-B-B and PAdES-B-LTA (DSS, document timestamp), RFC 3161 timestamps, OCSP responses, a JKS key store. The tests
  need no personal data, and none is stored in the repository.
- **The PKI layer and ua-sign** (`Pki/Asn1` … `Pki/Xades`, `Cli/`): DER against BouncyCastle; the real certificates
  parsed field by field as BouncyCastle parses them; JKS against the independent test implementation in both
  directions; C14N against Microsoft's implementation (used only in the tests); every signature the package makes is
  verified by the BouncyCastle-based recipes of the tests, and every signature of the test builders by the package;
  HTTP time-stamping and OCSP through a local server; the command line end to end. A mutation check (17 deliberate
  bugs, each caught) is described in [docs/implementation-notes.md](docs/implementation-notes.md).

## Performance

Apple M2, .NET 10, one core, hardware carry-less multiplication (PMULL):

| Curve | multiply, ns | square, ns | invert, µs | kP, µs | sign, µs | verify, µs |
|---|---:|---:|---:|---:|---:|---:|
| PB 163 | 39 | 32 | 6.1 | 65 | 67 | 135 |
| PB 257 | 40 | 30 | 8.5 | 120 | 122 | 257 |
| PB 431 | 113 | 58 | 26.7 | 427 | 431 | 879 |
| ONB 173 | 55 | 31 | 6.0 | 85 | 89 | 177 |
| ONB 233 | 91 | 39 | 9.7 | 170 | 176 | 349 |
| ONB 431 | 197 | 50 | 23.5 | 618 | 625 | 1260 |

Without the hardware instruction (`--portable`) everything is 3–6 times slower. Compared with the 2010 implementation
this library replaces: ONB multiplication at m = 173 went from 217 µs to 55 ns, an ONB signature at m = 173 from 1.3 s to
89 µs (≈ 15,000×), kP in PB at m = 431 from 35 ms to 0.43 ms.

### What makes ONB fast

1. **ONB multiplication is reduced to ordinary polynomial multiplication.** For a type 2 ONB, p = 2m + 1 is prime and
   x = γ + γ⁻¹, where γ is a primitive p-th root of unity. The basis {x^(2^i)} is a permutation of the elements
   s_k = γ^k + γ^(−k), k = 1..m, and for them s_i·s_j = s_(i+j) + s_|i−j|. The product is therefore obtained from two
   carry-less polynomial multiplications (A·B and A·B*, where B* is B with its bits reversed) and a "folding" of the
   exponents. Inside the library ONB elements are kept in this permuted form; they are converted to the standard form
   (5.3) only on input and output. Polynomial multiplication uses PMULL (ARMv8) / PCLMULQDQ (x86) when available.
2. **Montgomery ladder** (López–Dahab, projective X/Z coordinates): each bit of the scalar costs 6 multiplications and
   5 squarings, with no inversions; a single inversion at the end. The ladder performs the same operations for every
   bit of the secret scalar.

## Limitations

- The library has not been audited. Big-integer arithmetic is `System.Numerics.BigInteger` (not constant time), and
  the portable carry-less multiplication uses a 4-bit window table. The Montgomery ladder and the hardware path are
  regular, but protection against side-channel attacks was not a goal.
- `UA.Cryptography` itself has no ASN.1/X.509/CMS/XML layer; that is `UA.Cryptography.Pki`. It does not do PAdES,
  CRLs, archive timestamps, PKCS#12 or IIT key containers, and does not evaluate certificate policies
  ([docs/ua-sign.md](docs/ua-sign.md), "What is not supported").
- By default random numbers come from the OS `RandomNumberGenerator`; the generator of Appendix А
  (`Dstu4145RandomGenerator`) can be passed to `Dstu4145Signer`.

## Repository layout

```
src/UA.Cryptography.Pki/          DER, X.509, JKS, CMS/CAdES, TSP, OCSP, C14N, XAdES, ASiC, paths (net8.0)
src/UA.Cryptography.Cli/          ua-sign, the command-line tool (net10.0)
scripts/                          launch scripts for ua-sign (.sh and .ps1), publish, demo
src/UA.Cryptography/              the library (net8.0, no dependencies)
  Math/                           GF(2)[x], PB and ONB fields, basis conversion, primality
  EC/                             curve, points, Montgomery ladder
  Dstu4145/                       parameters, curves of Appendix Г, signature, encoding, generator of Appendix А
  Gost/                           GOST 28147-89, GOST 34.311-95
  Dstu7564/                       DSTU 7564:2014 (Kupyna)
  Dstu7624/                       DSTU 7624:2014 (Kalyna) and its modes
  Common/                         S-boxes shared by DSTU 7564/7624
tests/UA.Cryptography.Tests/      xUnit; folders mirror the library namespaces
  Pki/, Signatures/               certificates and signature formats; Pki/<namespace>/ the PKI layer
  Cli/                            ua-sign end to end
  Support/                        synthetic PKI, builders and format verification
  TestData/                       public certificates and reference vectors
bench/UA.Cryptography.Benchmarks/ benchmark (Markdown table)
tools/dstu7624-vectors/           generator of Kalyna reference vectors on BouncyCastle Java
docs/                             signature formats, implementation notes, porting
```

## Documentation

- [docs/signature-formats.md](docs/signature-formats.md) — XAdES, CAdES, PAdES, ASiC, timestamps and OCSP in the
  Ukrainian PKI, and how to verify them.
- [docs/ua-sign.md](docs/ua-sign.md) — the command-line tool, its scripts, and the PKI library underneath.
- [docs/provider-formats.md](docs/provider-formats.md) — the formats PrivatBank (CAdES-T `.sig`) and "Дія" (ASiC-E,
  XAdES-B-LT) hand out, and how `ua-sign` makes and verifies each of them.
- [docs/implementation-notes.md](docs/implementation-notes.md) — errors in the text of the standard, PKI conventions,
  what verifies each layer, differences from the 2010 project.
- [docs/porting.md](docs/porting.md) — porting to other languages.

## License

[MIT](LICENSE). The DSTU 7624 code is translated from BouncyCastle Java (MIT); the base points of the recommended
curves were published by the cryptography.org.ua project — see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
