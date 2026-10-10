# CZO trust anchors

Self-signed DSTU 4145 root certificates of Ukraine's **Central Certification Authority**
(Центральний засвідчувальний орган), used as public trust anchors in the tests.

- **Source:** the official CA bundle published at <https://czo.gov.ua/download/certificates/CACertificates.p7b>
  (1001 certificates; the self-signed CZO roots were extracted from it).
- **Nature:** public government certificates — no private data; safe to commit.
- **Basis:** every DSTU 4145 certificate in the national PKI uses the **polynomial basis**
  (degree m = 257 as a trinomial, m = 431 as a pentanomial, both as explicit parameters and as the
  named curves `…3.1.1.2.6` / `…3.1.1.2.9`). The optimal-normal basis (DSTU table Г.2) is **not** used
  in any real certificate. All CZO roots here are m = 431.
- **Signature hash:** older roots use GOST 34.311; the newest (2036) uses DSTU 7564-256 (Kupyna).

Each file's self-signature is verified by this library in `CzoTrustAnchorTests`.
File names encode the expiry year and the signature hash, e.g. `czo-root-2030-gost34311.cer`.
