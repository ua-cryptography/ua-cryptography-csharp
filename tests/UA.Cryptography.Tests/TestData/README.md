# Test data

Everything here is public: no personal data, no private keys, no real signed documents. Signatures in every
format (CAdES, XAdES, ASiC, PAdES, time-stamps, OCSP) are produced at test time by a synthetic PKI
(`Support/Hierarchy.cs`), so they never need to be committed.

| Folder | Contents | Used by |
|---|---|---|
| `certificates/historical/` | Certificates of Ukrainian certification authorities issued in 2005 – 2015 (expired) | `Pki/HistoricalCertificateTests` |
| `certificates/czo-roots/` | Current self-signed roots of the Central Certification Authority (ЦЗО) | `Pki/CzoTrustAnchorTests`, `Pki/ChainToTrustAnchorTests` |
| `certificates/intermediates/` | A current qualified provider's CA certificate issued by a CZO root | `Pki/ChainToTrustAnchorTests` |
| `vectors/` | DSTU 7624 reference vectors produced by BouncyCastle Java (`tools/dstu7624-vectors`) | `Dstu7624/Dstu7624Tests` |

Never add real signatures, key containers (`.jks`, `.pfx`, `Key-6.dat`, `*.ZS2`, …) or certificates of natural
persons here: `.gitignore` refuses the common key-container extensions as a safety net.
