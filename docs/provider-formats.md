# Provider signature formats

Two signature formats that Ukrainian qualified providers hand out, described from real signatures examined in
October 2026, and how `ua-sign` makes and verifies each of them:

| Name in this repository | What it is | File | Who makes it |
|---|---|---|---|
| **PrivatBank CAdES-T** | CAdES-B-T, data inside (an "internal" signature) | `document.sig` | PrivatBank |
| **"Дія" ASiC-E** | ASiC-E container with a detached XAdES-B-LT | `document.asice` | "Дія.Підпис" |

Both use **DSTU 4145 with DSTU 7564-256** (Kupyna-256) and keys on the 257-bit curve of table Г.1. The general rules —
byte order, identifiers, how each container stores the signature value — are in
[signature-formats.md](signature-formats.md); this document records what each provider puts where.

What is tested: for each format, `ua-sign` signs with a key from a JKS store and the result is checked against the
provider's profile by an implementation independent of the package (BouncyCastle, `System.Xml`), then verified by
`ua-sign verify`; and a signature built the way the provider builds it — including what the provider leaves out — is
verified by `ua-sign verify` (`ProviderFormatTests`, the profiles in `Support/ProviderProfiles.cs`). The same profile
checks pass on the real signatures, which are not in the repository: they carry personal data.

---

## 1. PrivatBank CAdES-T (`.sig`)

### Names

- ETSI EN 319 122-1: **CAdES-B-T** (baseline, with a signature time-stamp);
- ETSI TS 101 733 (older): **CAdES-T** — the name `ua-sign` prints;
- in Ukrainian tools: an internal signature (внутрішній підпис) — the data is inside, as opposed to a detached one;
- in CMS terms: `SignedData` with encapsulated content (`ua-sign` calls it enveloped).

The bank uses the extension `.sig`; `.p7s` is the usual one for the same structure and `ua-sign` defaults to it.

### Structure

```text
ContentInfo { id-signedData }
└── SignedData  version 1
    ├── digestAlgorithms        { DSTU 7564-256 }
    ├── encapContentInfo        id-data, the document itself
    ├── certificates            the signer's certificate only
    └── signerInfos             one SignerInfo, version 1
        ├── sid                 issuerAndSerialNumber
        ├── digestAlgorithm     DSTU 7564-256 (1.2.804.2.1.1.1.1.2.2.1)
        ├── signedAttrs         contentType, signingTime, messageDigest, signingCertificateV2
        ├── signatureAlgorithm  DSTU 4145 with DSTU 7564-256 (1.2.804.2.1.1.1.1.3.6.1.1)
        ├── signature           D = s‖r, 64 bytes, little-endian
        └── unsignedAttrs       signatureTimeStampToken
```

| Attribute | Where | Value |
|---|---|---|
| contentType `1.2.840.113549.1.9.3` | signed | `id-data` |
| signingTime `1.2.840.113549.1.9.5` | signed | `UTCTime`, whole seconds |
| messageDigest `1.2.840.113549.1.9.4` | signed | DSTU 7564-256 of the document |
| signingCertificateV2 `1.2.840.113549.1.9.16.2.47` | signed | one `ESSCertIDv2`: the algorithm written out, the DSTU 7564-256 of the certificate, and `issuerSerial` — the issuer as a `directoryName` and the serial number |
| signatureTimeStampToken `1.2.840.113549.1.9.16.2.14` | unsigned | RFC 3161 token over the `signature` octets |

The time-stamp token: policy `1.2.804.2.1.1.1.2.3.4.1.1` (DSTU 7564), the imprint DSTU 7564-256 of the signature value,
no nonce, signed by the bank's TSP server with contentType, signingTime, messageDigest and signingCertificateV2 — and
**without the TSP server's certificate**.

What the signature leaves out: the CA's certificate, the TSP server's certificate, any revocation data. That is what
makes it a T and not an LT signature, and why it cannot be fully verified offline.

### Trust

```text
NBU root "Засвідчувальний центр" (UA-00032106-2611, m = 431, until 2036)    tests/…/certificates/nbu-roots/
├── КНЕДП АЦСК АТ КБ "ПриватБанк" (UA-14360570-2610)                       tests/…/certificates/intermediates/privatbank-knedp.cer
│   ├── the customer's certificates (signing; key agreement)
│   └── OCSP-сервер КНЕДП … (UA-14360570-2613)
├── TSP-сервер КНЕДП АЦСК АТ КБ "ПриватБанк" (UA-14360570-2611)
└── OCSP-сервер Засвідчувальний центр
```

Banks' providers are certified under the National Bank's root, not under a ЦЗО root. The customer's certificate names
the services: OCSP `http://acsk.privatbank.ua/services/ocsp/`, time-stamping `http://acsk.privatbank.ua/services/tsp/`,
and caIssuers `http://acsk.privatbank.ua/arch/download/PB-2026-NBU.p7b` — a certificate bundle holding the CA, the TSP
and OCSP servers and the NBU root, i.e. everything the signature leaves out.

### The key store

The bank issues the key in a Sun JKS store (signature-formats.md, section 14) with one `PrivateKeyEntry`. The chain is
stored **root first** — root, CA, the signing certificate (keyUsage digitalSignature, nonRepudiation) — followed by the
certificate of the key-agreement key (m = 431, keyUsage keyAgreement), whose private key travels in IIT attributes of
the `PrivateKeyInfo`. `ua-sign` finds the signing certificate by its public key and rebuilds the path from it.

### Making it

```bash
ua-sign sign --keystore key.jks --format cades --level T --in document.txt --out document.txt.sig
```

Without `--tsa`, the time-stamping service is the one the certificate names. The result has the profile above; it
differs from the bank's only in the time-stamp token, which carries a nonce and the TSP server's certificate — so the
time-stamp can be checked offline. (The bank's sample examined was made with a different certificate of the same
customer than the one in the key store the bank issued; the format does not depend on it.)

### Verifying it

```bash
ua-sign verify --in document.txt.sig --trust nbu-root-2036-dstu7564.cer --online
```

`--online` downloads the caIssuers bundle (once) and completes both the signer's path and the time-stamp, then asks the
OCSP responders: all checks pass. Offline the CA and the TSP certificates are missing: the time-stamp is reported as not
verified (a warning, and the claimed signing time is used instead), and with `--trust` the signer's path cannot reach the
root (a failure); `--certs` with the CA and TSP certificates, or `--online`, completes it.

Tests: `ProviderFormatTests.PrivatBankSigIsMadeByUaSignAndVerifies` (a JKS laid out as the bank issues it, and a key
from `ua-sign keygen`), `ProviderFormatTests.PrivatBankSigAsTheBankMakesItVerifies` (offline, online, tampered),
`CadesSignerTests.SigningCertificateV2NamesTheIssuerAndSerialNumber`,
`CadesSignerTests.TimeStampWithoutTheServiceCertificateIsCompletedFromCaIssuers`,
`JksKeyStoreTests.ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered`.

---

## 2. "Дія" ASiC-E (`.asice`)

### Names

- ETSI EN 319 162-1: **ASiC-E** (extended container) with a **XAdES-B-LT** signature (ETSI EN 319 132-1) — baseline with
  a signature time-stamp and the long-term validation values;
- the XAdES signature is detached: it references the document inside the container by name.

### The container

A ZIP archive, entries in this order:

| Entry | Compression | Contents |
|---|---|---|
| `mimetype` | stored, first | `application/vnd.etsi.asic-e+zip` |
| `<document>` | deflate | the signed document, under its own name |
| `META-INF/manifest.xml` | deflate | OpenDocument manifest: `/` with the ASiC-E media type, the document with `application/octet-stream` |
| `META-INF/signatures001.xml` | deflate | the XAdES signature |

### The signature

```text
<?xml version="1.0" encoding="utf-8" standalone="no"?>
asic:XAdESSignatures                    xmlns:asic, ds, xades, xsi declared here
└── ds:Signature Id="id-<32 hex>"
    ├── ds:SignedInfo
    │   ├── CanonicalizationMethod      http://www.w3.org/2001/10/xml-exc-c14n#
    │   ├── SignatureMethod             http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256
    │   ├── Reference Id="id-…-1" Type="" URI="<document>"
    │   │       DigestMethod dstu7564-256, DigestValue = DSTU 7564-256 of the document
    │   └── Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-id-…"
    │           Transform exc-c14n, DigestMethod dstu7564-256
    ├── ds:SignatureValue               base64 of D (64 bytes), over exc-c14n(SignedInfo)
    ├── ds:KeyInfo/X509Data/X509Certificate   the signer's certificate
    └── ds:Object/xades:QualifyingProperties Target="#id-…"
        ├── xades:SignedProperties Id="xades-id-…"
        │   ├── SignedSignatureProperties
        │   │   ├── SigningTime                       e.g. 2026-01-01T12:00:00Z (whole seconds)
        │   │   └── SigningCertificateV2/Cert/CertDigest   DSTU 7564-256 of the certificate
        │   └── SignedDataObjectProperties
        │       └── DataObjectFormat ObjectReference="#id-…-1"   MimeType application/octet-stream
        └── xades:UnsignedProperties/UnsignedSignatureProperties
            ├── SignatureTimeStamp Id="TS-…"
            │   ├── ds:CanonicalizationMethod  exc-c14n
            │   └── EncapsulatedTimeStamp Id="ETS-…"   token over exc-c14n(ds:SignatureValue)
            ├── CertificateValues        the CA, the ЦЗО root, the OCSP server
            └── RevocationValues/OCSPValues
                └── EncapsulatedOCSPValue   one OCSPResponse, about the signer's certificate
```

The time-stamp token (policy `1.2.804.2.1.1.1.2.3.4.1.1`) carries the TSP server's certificate, so the container holds
everything an offline check needs except a revocation status for the CA and the TSP server.

**The OCSP response's CertID has a zero `issuerKeyHash`**: 32 zero bytes instead of the hash of the issuer's key; the
hash algorithm is DSTU 7564-256 and `issuerNameHash` and `serialNumber` are right. Such a response is matched by name
and serial number, and the responder's authorization by the issuer still binds it to the issuer's key
(signature-formats.md, section 5).

### Trust

```text
ЦЗО root "Центральний засвідчувальний орган" (2036, DSTU 7564)   tests/…/certificates/czo-roots/czo-root-2036-dstu7564.cer
├── "Дія". Кваліфікований надавач електронних довірчих послуг     tests/…/certificates/intermediates/dia-knedp.cer
│   ├── the signer's certificate
│   └── OCSP-сервер КНЕДП "Дія"
└── TSP-сервер КНЕДП "Дія"
```

### Making it

The "Дія.Підпис" key is not handed out as a file, so the format is made with another key: any JKS key whose
certificate is issued by a CA with an OCSP responder (a bank-issued key, for example).

```bash
ua-sign sign --keystore key.jks --format asic-e --level LT --in document.txt
```

The services are the ones the certificates name (`--tsa`, `--ocsp` override them). The result has the profile above.
What differs from "Дія", none of it affecting validity: the identifiers (`S-<hex>`, `…-Reference-1`,
`…-SignedProperties`, an Id on `ds:SignatureValue`), no empty `Type` on the data reference, the MIME type by the file
extension (`text/plain` for `.txt`), the namespaces declared where they are used, the TSP server's certificate also in
`CertificateValues`, and OCSP responses for the signer **and** its CA, with the real `issuerKeyHash`.

A key from `ua-sign keygen` gives levels B and T of this format (T with `--tsa`, as a self-signed certificate names no
time-stamping service); LT needs a CA-issued certificate, since a self-signed one has no OCSP responder.

### Verifying it

```bash
ua-sign verify --in document.asice --trust czo-root-2036-dstu7564.cer
```

Offline, all checks pass except the revocation status of the CA and the TSP server, which "Дія" does not embed
(warnings); `--online` asks for them.

Tests: `ProviderFormatTests.DiiaAsicEIsMadeByUaSignAndVerifies`, `ProviderFormatTests.DiiaAsicEAsDiiaMakesItVerifies`
(including a changed document), `PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial`.
