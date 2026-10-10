# DSTU 4145 signature formats in the Ukrainian PKI

A reference for the electronic signature formats met in practice and for how to verify them with the code of this
library. The conventions described here were established on real qualified signatures and certificates of the national
PKI; in the repository they are reproduced by a **synthetic PKI** (section 13), so the tests need no personal data.

**The goal is to be able to verify signatures of any format.** The end of the document lists what is already covered
by tests and what remains to be done.

Code references: `src/UA.Cryptography` (cryptography), `src/UA.Cryptography.Pki` (the formats themselves: DER, X.509,
JKS, CMS/CAdES, timestamps, OCSP, XML canonicalization, XAdES, ASiC — no third-party dependencies),
`tests/UA.Cryptography.Tests` — format tests in `Signatures/` (`CadesTests`, `XadesTests`, `PadesTests`) and
`Pki/<namespace>/`, certificates in `Pki/`, shared helpers in `Support/` (`UaPki` — verification, `TestPki`/`Hierarchy`
— the synthetic PKI, `*Builder` — building signatures). The helpers of `Support/` are a second, independent
implementation of the same recipes: there ASN.1 is parsed by BouncyCastle and XML is canonicalized by
`System.Security.Cryptography.Xml`, and every signature of one implementation is verified by the other (section 13).
The hashes and DSTU 4145 are the library's own code in both.

The Ukrainian abbreviations used below: **ЦЗО** — the Central Certification Authority (Центральний засвідчувальний
орган), the national root; **ЦСК** — a key certification centre, i.e. a qualified CA; **КНЕДП** — a qualified trust
service provider.

---

## 1. The main rule: byte order

In every format checked and for both hashes (GOST 34.311 and DSTU 7564) the same convention applies:

| What | How it is stored | What to do when verifying |
|---|---|---|
| The hash that is signed | the hash function output as is | **reverse the bytes** before transformation 5.9 (hash → field element) |
| The signature value D = S‖R (5.10) | **little-endian** | reverse the bytes, then the high half is s, the low half is r |
| Hashes inside structures (DigestValue in XML, messageDigest in CMS, certificate hashes, timestamp imprints) | the hash function output as is | compare directly, reverse nothing |
| Compressed point (public key, base point), coefficient B | little-endian if the key OID is `…3.1.1`; big-endian if `…3.1.1.1.1` | reverse for "LE" and recover the point by 6.10 |

In code this is a single function (`UaPki.VerifyDstu4145` in the tests, `Dstu4145PublicKey.VerifyHash` in the
package):

```csharp
signer.VerifyHash(publicKey, Reverse(hash), Reverse(signatureValue));
```

Where the signature value lives depends on the container:

| Container | Field | Contents |
|---|---|---|
| X.509 certificate, OCSP response | `signature BIT STRING` | a DER `OCTET STRING` containing D (64 bytes for m = 257, 108 bytes for m = 431) |
| CMS / CAdES, RFC 3161 timestamp | `SignerInfo.signature OCTET STRING` | D directly, with no nested `OCTET STRING` |
| XAdES | `ds:SignatureValue` | base64 of D |
| PAdES | `/Contents <hex>` of the signature dictionary | CMS (section 9), padded with zeros to a fixed size |

---

## 2. Identifiers

All OIDs are in the `1.2.804.2.1.1.1` arc (Ukraine).

### Algorithms

| OID | Purpose |
|---|---|
| `1.2.804.2.1.1.1.1.2.1` | GOST 34.311-95 hash |
| `1.2.804.2.1.1.1.1.2.2.1` / `.2.2.2` / `.2.2.3` | DSTU 7564 hash (256 / 384 / 512) |
| `1.2.804.2.1.1.1.1.3.1.1` | DSTU 4145 key, "LE" variant; also the "DSTU 4145 + GOST 34.311" signature algorithm |
| `1.2.804.2.1.1.1.1.3.1.1.1.1` | DSTU 4145 key, "BE" variant |
| `1.2.804.2.1.1.1.1.3.1.1.2.0` … `.2.9` | named curves: the i-th curve of table Г.1 (m = 163, 167, 173, 179, 191, 233, 257, 307, 367, 431) |
| `1.2.804.2.1.1.1.1.3.6.1.1` | the "DSTU 4145 + DSTU 7564-256" signature algorithm |

### URIs in XML (XAdES)

| URI | Purpose |
|---|---|
| `http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256` | SignatureMethod: DSTU 4145 + DSTU 7564-256 |
| `http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311` | SignatureMethod: DSTU 4145 + GOST 34.311 |
| `http://www.w3.org/2001/04/xmlenc#dstu7564-256` | DigestMethod: DSTU 7564-256 |
| `http://www.w3.org/2001/04/xmlenc#gost34311` | DigestMethod: GOST 34.311 |
| `http://www.w3.org/2001/10/xml-exc-c14n#` | canonicalization (exclusive C14N) |

### CMS attributes (CAdES)

| OID | Attribute | Where | Contents |
|---|---|---|---|
| `1.2.840.113549.1.9.3` | contentType | signed | `id-data` |
| `1.2.840.113549.1.9.5` | signingTime | signed | signing time |
| `1.2.840.113549.1.9.4` | messageDigest | signed | hash of the data |
| `1.2.840.113549.1.9.16.2.47` | signingCertificateV2 | signed | hash of the signer's certificate (the algorithm is given inside) |
| `1.2.840.113549.1.9.16.2.20` | contentTimeStamp | signed | timestamp over the data |
| `1.2.840.113549.1.9.16.2.14` | signatureTimeStampToken | unsigned | timestamp over the signature value (level T) |
| `1.2.840.113549.1.9.16.2.21` | completeCertificateRefs | unsigned | hashes of the chain certificates (level C) |
| `1.2.840.113549.1.9.16.2.22` | completeRevocationRefs | unsigned | hashes of the OCSP responses / CRLs (level C) |
| `1.2.840.113549.1.9.16.2.23` | certValues | unsigned | the certificates themselves (level X-Long) |
| `1.2.840.113549.1.9.16.2.24` | revocationValues | unsigned | the OCSP responses / CRLs themselves (level X-Long) |

---

## 3. Key and parameters in a certificate

`SubjectPublicKeyInfo`:

- `algorithm` — the key OID (`…3.1.1` "LE" or `…3.1.1.1.1` "BE");
- `parameters` — `SEQUENCE { curve, [DKE] }`:
  - the curve is either a named curve OID (`…3.1.1.2.i`) or an explicit structure
    `ECBinary { field SEQUENCE { m, k | SEQUENCE { k, j, l } }, A INTEGER, B OCTET STRING, n INTEGER, BP OCTET STRING }`,
    where BP is the compressed base point;
  - DKE — 64 bytes, the GOST 28147 S-box table for GOST 34.311 (`Gost34311.FromDke`). If it is absent, DKE No. 1
    (`Gost34311.DefaultDke`) is used. The "Дія" certificates have no DKE;
- `subjectPublicKey` — a `BIT STRING` wrapping an `OCTET STRING` that contains the compressed point Q.

Parameters seen in the wild: all current certificates (the "Дія" CA, the "Дія" TSP and OCSP, the ЦЗО root) give the
curve **explicitly**, but the values match table Г.1 **together with the base point**: m = 257 (trinomial k = 12,
A = 0) for "Дія", m = 431 for the ЦЗО root. The old ЦЗО root (2005) used m = 431 with a different base point, BITiS a
named curve with m = 257, and UCC (УСЦ) an explicit m = 257.

Parsing is done by `UaPki.ReadPublicKey`; after parsing, the parameters go through the checks of clause 8 and the key
through 10.1.

---

## 4. X.509 certificate

1. Hash the DER encoding of `TBSCertificate` with the algorithm from the certificate's `signatureAlgorithm`
   (`…3.6.1.1` → DSTU 7564-256, `…3.1.1` → GOST 34.311 with the issuer's DKE or DKE No. 1).
2. The issuer's key comes from its certificate (section 3).
3. Signature: `signature BIT STRING` → `OCTET STRING` → D; verify by the rule of section 1.

Tests: `HistoricalCertificateTests` (5 certificates from 2005–2015, GOST 34.311 + DKE), `CzoTrustAnchorTests` (the ЦЗО
roots, GOST 34.311 and DSTU 7564), `ChainToTrustAnchorTests`, `XadesTests.SignerCertificateIsIssuedByEmbeddedCa`.

## 5. OCSP response

`OCSPResponse` → `responseBytes` (type `1.3.6.1.5.5.7.48.1.1`) → `BasicOCSPResponse`.

- The signature is over the DER of `tbsResponseData`; the algorithm is `signatureAlgorithm` (in practice `…3.6.1.1`).
- `responderID` is by name; the responder's certificate is embedded in the response itself (`certs`).
- The signature value is stored as in a certificate (`BIT STRING` → `OCTET STRING` → D).
- `CertID` uses the DSTU 7564-256 hash; the `good` status is tag 0.
- The "Дія" responder fills `CertID.issuerKeyHash` with zeros; such a response is matched by `serialNumber` and
  `issuerNameHash` alone, and the responder's authorization by the issuer binds it to the issuer's key
  (`PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial`).

Tests: `TestPkiTests.OcspResponseIsSignedByTheResponderAndGood`, `CadesTests.LongTermValidationDataIsConsistent`,
`XadesTests.RevocationValuesAreSignedAndGood`, `PadesTests.DocumentSecurityStoreIsComplete` (in PDF and XAdES the OCSP
responses are stored as full `OCSPResponse`s, in CAdES as `BasicOCSPResponse`s).

## 6. Timestamp (RFC 3161)

The token is a CMS SignedData with `id-ct-TSTInfo` content (`1.2.840.113549.1.9.16.1.4`).

- `TSTInfo.messageImprint` is the hash of what is being timestamped (the algorithm is given there too; the hash is
  **not** reversed):
  - a timestamp over the data (CAdES contentTimeStamp) — the hash of the data;
  - a timestamp over the signature (CAdES signatureTimeStampToken) — the hash of the `SignerInfo.signature` value;
  - a timestamp over the signature in XAdES (`xades:SignatureTimeStamp`) — the hash of the canonicalized
    `ds:SignatureValue` element;
  - a document timestamp in PDF (`/DocTimeStamp`) — the hash of the bytes of its `/ByteRange` (the whole file except
    its own `/Contents`).
- The token signature is over the DER of the signed attributes of its `SignerInfo` (messageDigest = hash of TSTInfo,
  signingCertificateV2 = hash of the timestamping service certificate), by the rule of section 1.
- The service's hash and signature algorithm match the request: DSTU 7564 + `…3.6.1.1` or GOST 34.311 + `…3.1.1`.
- Policies: `1.2.804.2.1.1.1.2.3.1` (with GOST 34.311), `1.2.804.2.1.1.1.2.3.4.1.1` (with DSTU 7564).

The "Дія" timestamps are signed by **«TSP-сервер КНЕДП "Дія"»** (the "Дія" TSP server); its certificate is issued
directly by the **ЦЗО root** (not by the "Дія" CA), and the key is on the m = 257 curve. The service certificate is not
embedded in every token: timestamps over XAdES and CAdES-X Long signatures usually include it, in PDF it is in the DSS,
and in CAdES-T inside ASiC-S it may be missing altogether — then it is looked up by `SignerID` (issuer + serial number)
among the known certificates and checked against the hash in signingCertificateV2 (`UaPki.FindTimeStampSigner`).

The tests check the imprints and signatures of all timestamps (`TestPkiTests.TimeStampTokenCoversDataAndIsSignedByTheTsa`,
`CadesTests.TimeStampsCoverDataAndSignature`, `XadesTests.TimeStampCoversTheSignature`, `PadesTests.TimeStampsVerify`).

---

## 7. XAdES (XML)

An XML-DSig signature with ETSI qualifying properties (`http://uri.etsi.org/01903/v1.3.2#`).

Structure (detached, level B-LT):

```
ds:Signature
  ds:SignedInfo
    ds:CanonicalizationMethod   exc-c14n
    ds:SignatureMethod          …dstu4145-dstu7564-256 | …dstu4145-gost34311
    ds:Reference URI="<file>"   DigestMethod + DigestValue (hash of the file)
    ds:Reference URI="#xades-…" Type=…#SignedProperties, Transform exc-c14n, DigestValue
  ds:SignatureValue             base64(D), D little-endian
  ds:KeyInfo/ds:X509Data/ds:X509Certificate   the signer's certificate
  ds:Object/xades:QualifyingProperties
    xades:SignedProperties      SigningTime, SigningCertificateV2 (certificate hash), DataObjectFormat
    xades:UnsignedProperties
      xades:SignatureTimeStamp  timestamp (level T)
      xades:CertificateValues   certificates of the CA, the root, OCSP (level LT)
      xades:RevocationValues    OCSP responses (level LT)
```

Verification (`XadesTests.SignatureVerifies`):

1. For each `ds:Reference`: an external file — the hash of the file bytes; `#id` — the hash of the exc-c14n of the
   element found by `Id`. Compare with `DigestValue` directly.
2. Compare the hash of the certificate from `KeyInfo` with `SigningCertificateV2/Cert/CertDigest`.
3. Hash the exc-c14n of the `ds:SignedInfo` element → verify `SignatureValue` by the rule of section 1.

Canonicalization: `XmlDsigExcC14NTransform` over a document loaded from the element's `OuterXml`
(`PreserveWhitespace = true`); `OuterXml` carries the required namespace declarations, and exc-c14n drops the unused
ones (`asic`, `xsi`).

## 8. ASiC-E (`.asice`)

ZIP: `mimetype` (first, uncompressed, `application/vnd.etsi.asic-e+zip`), the data files, `META-INF/manifest.xml`
(OpenDocument manifest: `/` and each data file), `META-INF/signatures*.xml` — root `asic:XAdESSignatures`
(`http://uri.etsi.org/02918/v1.2.1#`) containing an ordinary `ds:Signature` from section 7. The `URI` references point
to files inside the archive. Verification is the same as for XAdES (`XadesTests.SignatureVerifies` with ASiC-E
packaging).

## 9. CAdES (CMS)

`ContentInfo` → `SignedData`; a single `SignerInfo`, the signer is identified by issuer and serial number, the signer's
certificate is in `certificates`.

Verification (`CadesTests.SignatureVerifies`):

1. `messageDigest` = hash of the data (the algorithm is the signer's `digestAlgorithm`).
2. `signingCertificateV2` = hash of the signer's certificate; IIT and the banks also write `issuerSerial` (the issuer
   as a `directoryName` and the serial number), which must then name the same certificate. The package writes it too
   (`CadesSignerTests.SigningCertificateV2NamesTheIssuerAndSerialNumber`).
3. Hash the DER of the signed attributes (`SET OF`, as `GetEncodedSignedAttributes()`) → verify `SignerInfo.signature`
   (D directly, little-endian) by the rule of section 1.

Variants:

- **Detached** — no data inside (`encapContentInfo` without content), the data is alongside (ASiC-S).
- **Enveloped** (`.p7s`) — the data is in `encapContentInfo` (`id-data`).

Levels met in practice:

- **CAdES-T** — + signatureTimeStampToken. PrivatBank hands out its signatures in this shape as `.sig`: enveloped, only
  the signer's certificate in `certificates`, and a token without the time-stamping service's certificate. Both missing
  certificates — the CA and the TSA — are in the bundle at the signer certificate's caIssuers address, which the
  verifier downloads when allowed (`CadesSignerTests.TimeStampWithoutTheServiceCertificateIsCompletedFromCaIssuers`);
- **CAdES-X Long** — + completeCertificateRefs / completeRevocationRefs (level C) + certValues / revocationValues.
  Rules for the references: `OtherCertID.otherCertHash` is the hash of the certificate DER;
  `OcspResponsesID.ocspRepHash` is the hash of the `BasicOCSPResponse` DER; the hash algorithm is given in the
  reference (usually DSTU 7564-256). Typical contents: the certificates of the CA and the ЦЗО root; OCSP responses from
  the CA (about the signer's certificate) and from ЦЗО (about the CA certificate), both `good`
  (`CadesTests.LongTermValidationDataIsConsistent`).

## 10. ASiC-S (`.asics`)

ZIP: `mimetype` (first, `application/vnd.etsi.asic-s+zip`), a single data file, `META-INF/signature.p7s` — a detached
CAdES (section 9). Test: `CadesTests.AsicSContainerIsWellFormedAndVerifies`.

## 11. PAdES (signature in PDF)

ETSI EN 319 142. A signed PDF is the original file **unchanged** plus successive incremental updates, each ending with
its own `%%EOF`. A B-LTA level signature has three of them:

1. **Signature** — field `/FT /Sig`, dictionary `/Type /Sig`, `/Filter /Adobe.PPKLite`,
   `/SubFilter /ETSI.CAdES.detached`:
   - `/ByteRange [0 a c d]` — the signed bytes: `[0, a)` and `[c, c + d)`, i.e. the whole file at signing time (up to
     the `%%EOF` of this update) except `/Contents <…>` itself (`a` is the position of `<`, `c` the position after `>`);
   - `/Contents <hex>` — a detached CAdES (section 9) padded with zeros; take the first DER object;
   - `messageDigest` = hash of the `/ByteRange` bytes; attributes: contentType, messageDigest, signingCertificateV2
     (no signingTime — the time is in `/M`); unsigned signatureTimeStampToken (level T).
2. **DSS** (Document Security Store, level LT) — `/Type /DSS` with `/Certs [ … ]` and `/OCSPs [ … ]` (`/CRLs` and
   `/VRI` also occur): references to streams (`/FlateDecode`), each holding a certificate DER or a full `OCSPResponse`.
   Usually these are the CA, the ЦЗО root, the TSP, the OCSP responder certificates and OCSP responses about the
   certificates of the signer, the CA and the TSP — all `good`. The signer's certificate is in the CMS, not in the DSS.
3. **Document timestamp** (level LTA) — `/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`: `/Contents` holds an
   RFC 3161 token, `messageImprint` = hash of the `/ByteRange` bytes, which now cover the whole file including the DSS.

Verification (`PadesTests`): the file starts with the original PDF; the `/ByteRange` of each signature covers
everything except its `/Contents` and ends at `%%EOF`; the last timestamp covers the whole file; the CAdES signature;
both timestamps (imprints and signatures, the TSP certificate taken from the DSS); the chain of every certificate up to
a self-signed root; the signatures and status of all OCSP responses; the presence of OCSP responses for the signer, its
CA and the TSP.

In the tests PDF is parsed with regular expressions (`Support/PdfInspector`: objects, latest object versions,
`FlateDecode` streams). Arbitrary PDFs need a real parser: cross-reference tables and streams (`/XRef`), object streams
(`/ObjStm`), indirect `/Length`.

---

## 12. Chain of trust

```
Центральний засвідчувальний орган (ЦЗО; root, self-signed, m = 431)
├── "Дія". Кваліфікований надавач електронних довірчих послуг (CA, m = 257)
│   ├── user certificates (m = 257, signed with DSTU 4145 + DSTU 7564)
│   └── OCSP-сервер КНЕДП "Дія"
├── TSP-сервер КНЕДП "Дія"            (timestamps)
└── OCSP-сервер ЦЗО
```

The synthetic PKI of the tests (`Support/Hierarchy`) has the same shape: Test Root CA (m = 431) → Test Issuing CA
(m = 257) → Test Signer; Test TSP Server and Test Root OCSP are issued by the root, Test OCSP by the issuing CA. All
certificates are signed with DSTU 4145 + DSTU 7564. The public certificates of the real chain (the ЦЗО roots and the
"Дія" CA) are in `tests/UA.Cryptography.Tests/TestData/certificates`, and their signatures are verified too.

---

## 13. How this is verified in the repository

Signatures of every format are created during the tests by the synthetic PKI (section 12) and verified by the recipes
of sections 1–11 — the same steps that were used to verify real qualified signatures while the conventions were being
established. Personal data and real signed documents never enter the repository (`.gitignore` also blocks key
containers).

| Test | Container | Format | Hash |
|---|---|---|---|
| `XadesTests` | XML next to the file | XAdES-B-B / B-T / B-LT | DSTU 7564-256, GOST 34.311 |
| `XadesTests` | ASiC-E (`.asice`) | XAdES-B-LT, `META-INF/signatures001.xml`, manifest | DSTU 7564-256 |
| `CadesTests` | `.p7s`, enveloped / detached | CAdES-B, CAdES-T (timestamps over the data and over the signature), CAdES-X Long | DSTU 7564-256, GOST 34.311 |
| `CadesTests` | ASiC-S (`.asics`) | CAdES-T, detached | GOST 34.311 |
| `PadesTests` | PDF | PAdES-B-B, PAdES-B-LTA (DSS and document timestamp) | DSTU 7564-256 |
| `TestPkiTests` | — | RFC 3161 timestamp, OCSP response, JKS | DSTU 7564-256, GOST 34.311 |
| `Pki/Cades/CadesSignerTests` | `.p7s` | the package's CAdES-B/T/X Long ↔ the BouncyCastle recipes; `CadesBuilder` ↔ the package | DSTU 7564-256, GOST 34.311 |
| `Pki/Xades/XadesSignerTests` | XML next to the files | the package's XAdES-B-B/T/LT ↔ Microsoft's C14N; `XadesBuilder` ↔ the package; wrapping | DSTU 7564-256, GOST 34.311 |
| `Pki/Asic/AsicContainerTests` | ASiC-S, ASiC-E | the package's containers and the builders', unsigned and replaced entries | DSTU 7564-256, GOST 34.311 |
| `Pki/Tsp`, `Pki/Services`, `Pki/Validation` | — | timestamps, HTTP TSP/OCSP through a local server, certification paths | DSTU 7564-256, GOST 34.311 |
| `Cli/UaSignTests` | every format | `ua-sign` keygen → sign → verify, levels T and LT over HTTP | DSTU 7564-256, GOST 34.311 |

The structural correctness of the synthetic timestamps and OCSP responses is additionally confirmed by BouncyCastle
(`TimeStampToken`, `BasicOcspResp`), and the byte order by the fact that the same verification functions (`UaPki`)
accept the real certificates of ЦЗО, the "Дія" CA and the CAs of 2005–2015.

---

## 14. Key containers

`UA.Cryptography.Pki` reads and writes one of them (`KeyStore/JksKeyStore`), and the tests keep an independent
implementation of the same format (`Support/Jks`): **Sun JKS** (the format in which PrivatBank, for example, issues keys). A `PrivateKeyEntry` record; the key is protected
by the "Sun key protector" (`1.3.6.1.4.1.42.2.17.1.1`: 20-byte salt ‖ key XOR a SHA-1 keystream ‖ SHA-1 of the password
and the key); the integrity of the store is SHA-1 over the password (UTF-16BE), the string "Mighty Aphrodite" and the
contents. Inside is a PKCS#8 `PrivateKeyInfo`: version 0, the `AlgorithmIdentifier` of a DSTU 4145 key (`…3.1.1` with
`{ named curve, DKE }`) and d as an `OCTET STRING` in **little-endian**. The certificate chain is stored next to the
key.

keytool stores the chain end entity first, but PrivatBank stores it **root first** — root, CA, the signing certificate
(keyUsage digitalSignature, nonRepudiation) — followed by the certificate of the key-agreement key on another curve
(keyUsage keyAgreement). That second key travels in IIT attributes of the `PrivateKeyInfo` (`1.3.6.1.4.1.19398.1.1.2.*`),
which signing does not need. The package therefore finds the key's certificate anywhere in the chain by its public key
and rebuilds the path from it up through its issuers, leaving out the rest
(`JksKeyStoreTests.ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered`).

The format was checked on a real key; only synthetic tests remain in the repository
(`TestPkiTests.JksRoundTripRecoversKeyAndChain`, `JksKeyStoreTests`: the two implementations read each other's stores).
The package also accepts several entries (choosing the signing key by alias or by keyUsage), trusted certificate
entries, Java's modified UTF-8 in aliases, and d written the BouncyCastle way (a DER INTEGER, big-endian, inside the
OCTET STRING). IIT containers (`Key-6.dat`, `.ZS2`) and PKCS#12 have not been analysed yet.

## 15. Which DKE GOST 34.311 hashes with

For certificates and OCSP responses the rule is established on real data: the DKE of the **issuer's** key, DKE No. 1
when there is none (section 4). For the data and the signed parts of CMS and XAdES (messageDigest, ds:Reference, the
signed attributes, ds:SignedInfo) the formats carry no DKE and no real signature with a non-default DKE has been
examined. The package therefore signs with the DKE of the signer's key and, when verifying, accepts the hash with the
signer's DKE or with DKE No. 1 (`PkiAlgorithms.CandidateHashes`). The two coincide for every current certificate:
neither the "Дія" certificates nor the keys `ua-sign keygen` creates carry a different table.

---

## 16. What is verified and what is not

Verified (tests):

- the document signature in all six variants (XAdES, ASiC-E, CAdES enveloped, ASiC-S/CAdES-T, CAdES-X Long,
  PAdES-B-LTA), the binding to the data and to the signer's certificate;
- certificate signatures: the synthetic chain up to the root; the real ЦЗО roots (GOST 34.311 and DSTU 7564), the "Дія"
  CA → the ЦЗО root, five CA certificates from 2005–2015;
- in CAdES-X Long, XAdES-B-LT and PAdES — the signatures of OCSP responses and their status; in CAdES-X Long —
  references ↔ values;
- the imprints and signatures of all timestamps, and finding the service certificate when it is not in the token.

Not done yet (needed for "any format"):

- **Certification path validation** by the rules: validity periods at the time of the signature/timestamp,
  keyUsage/extendedKeyUsage, basicConstraints, policies, qcStatements, binding to a trusted root (a trusted root list).
- **Revocation by CRL** and a check that the OCSP response is fresh relative to the signing time.
- **Higher levels**: XAdES-B-LTA / CAdES-A (archive timestamps), CAdES-X type 1/2 (timestamps over the references).
- **Multiple signers, countersignatures**, several signatures in one ASiC-E.
- **Other containers**: XAdES enveloped/enveloping; PDFs with several signatures, with changes after signing (DocMDP,
  checking that updates after the signature are permitted), with cross-references in streams (`/XRef`, `/ObjStm`).
- **Other parameters**: DSTU 7564-384/512, curves with m ≠ 257/431, the normal basis (not used in the national PKI).
- **PAdES in the package**: signing and verifying PDF needs a real PDF parser (cross-reference streams, object
  streams) and incremental updates; so far only the tests handle the simple PDFs of `PadesBuilder`.

Done in `UA.Cryptography.Pki` since the list was written: the library's own ASN.1, X.509, CMS and XML canonicalization;
the certification path with validity periods, CA flags, a trust anchor list and the authorization of OCSP responders;
several signatures in one ASiC-E.
