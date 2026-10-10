# Porting to other languages

The C# implementation is meant to be a reference: it has no dependencies beyond the standard library, and the only
processor-specific part is carry-less multiplication. Below are the order in which to port, the bit conventions that
are easy to get wrong, and the set of tests worth porting together with the code.

## Layers

Port bottom-up, running the tests of each layer at every step:

1. **`Math/Gf2Poly`** — polynomials over GF(2) in arrays of 64-bit words (least significant word first): carry-less
   multiplication, squaring (bit interleaving with zeros), shifts, bit reversal. Hardware multiplication: PMULL (ARMv8),
   PCLMULQDQ (x86); the portable variant is a 4-bit window (`Multiply64`) with a correction for the lost high bits.
2. **`Math/BinaryField`** + **`PolynomialBasisField`** + **`OptimalNormalBasisField`** — the field GF(2^m). The
   generic algorithms (Itoh–Tsujii, trace, half-trace, quadratic equation) are written in terms of multiplication and
   squaring, so they do not depend on the basis.
3. **`EC/BinaryCurve`** — the formulas of В.8 and the Montgomery ladder (López–Dahab) with y recovery; point
   compression.
4. **`Gost/*`** — GOST 28147 (block encryption and decryption), GOST 34.311 with the S-box table (DKE) as a parameter.
5. **`Dstu4145/*`** — parameters, the curves of Appendix Г, the encodings of 5.8–5.11, signing and verification, the
   random bit generator of Appendix А (on GOST 28147).
6. **`Dstu7564/*`** — Kupyna: the state is made of 64-bit columns (byte r of a column is row r, little-endian);
   SubBytes and MixColumns are merged into 8 tables built from the S-boxes at startup — a port can generate them with
   the same code instead of copying them. The S-boxes are shared with Kalyna (`Common/DstuSBoxes`).
7. **`Dstu7624/*`** — Kalyna and its modes: a translation of BouncyCastle Java 1.86, one file per mode; the reference
   vectors for any language are in `tests/UA.Cryptography.Tests/TestData/vectors/dstu7624-bc-java-1.86.json`.

Then the PKI layer (`src/UA.Cryptography.Pki`), which uses nothing but the standard library of the target language
(SHA-1/SHA-256, ZIP, an XML parser, HTTP):

8. **`Asn1/`** — a DER/BER reader that keeps the exact bytes of every element (signatures cover them) and a DER writer
   made of small functions; tests: `Pki/Asn1/DerTests`.
9. **`X509/`, `KeyStore/`** — certificates, the DSTU 4145 key in SubjectPublicKeyInfo and PKCS#8 (byte order by the key
   OID), the Sun JKS store; tests: the real certificates of `TestData`, `JksKeyStoreTests`.
10. **`Cms/`, `Tsp/`, `Ocsp/`, `Cades/`** — SignedData, timestamps, OCSP; the signed attributes are hashed as a SET
    (tag `31`), not with their `[0]` tag.
11. **`Xml/`** — Canonical XML 1.0 and Exclusive C14N 1.0 over the DOM of the language; port the documents of
    `XmlCanonicalizerTests` together with the expected outputs (they can be produced once with any C14N implementation).
12. **`Xades/`, `Asic/`, `Validation/`** — the formats and the certification path.

## Conventions that are easy to get wrong

- **The standard representation of a field element (5.3)** is an m-bit string written as a hexadecimal number. In PB,
  bit i is the coefficient of t^i. In ONB, the **most significant** bit (m − 1) is the coefficient of x, and the
  **least significant** bit 0 is the coefficient of x^(2^(m−1)); squaring is a cyclic shift right; the unit of the
  field is **all ones**.
- **A = 1 means the unit of the field**, not the bit string 00…01 (in ONB these are different things — see
  [implementation-notes.md](implementation-notes.md), sections 1.6 and 5).
- **Internal ONB representation.** Bit k (k = 1…m) holds the coefficient of s_k = γ^k + γ^(−k); bit 0 is always 0.
  The element x^(2^i) sits at bit k_i = 2^i mod p, "folded" into 1…m (if k_i > m, p − k_i is taken), p = 2m + 1.
  Standard bit j corresponds to x^(2^(m−1−j)), i.e. to internal bit k_(m−1−j).
- **ONB multiplication** (`OptimalNormalBasisField.Multiply`): P1 = A·B, P2 = A·B*, where B* is B reflected
  k → m + 1 − k. The result is the low bits of P1 (1…m) ⊕ (P2 ≫ (m + 1)) ⊕ reflect((P1 ≫ m) ⊕ P2, bits 1…m only).
  Squaring: S = the bits of A interleaved with zeros; the result is the low bits of S ⊕ reflect(S ≫ m, bits 1…m).
- **Hash (5.9).** The signature takes the binary string (h_{L_H−1}, …, h_0), most significant byte first. GOST 34.311
  outputs the bytes least significant first, so they must be reversed (`Dstu4145Signer.HashMessage`).
- **Truncation (5.8).** r is the low L(n) − 1 bits of the standard representation of h·F_e; without truncation the
  signature is self-consistent but incompatible (a bug of the old code).
- **Signature (5.10).** D = S‖R, each half L_D/2 bits, big-endian. In the Ukrainian PKI the same bytes are stored in
  reverse order, and the hash is reversed before 5.9 ([signature-formats.md](signature-formats.md), section 1).
- **Random numbers (6.3).** At most L(n) − 1 bits; the first bits generated are the most significant ones.
- **Errors in the text of the standard** ([implementation-notes.md](implementation-notes.md), section 1): the condition
  for an ONB to exist in В.2, the denominator of the addition formula in В.8, the digit of x_Q in Б.1.

## Tests worth porting

A minimal set that catches almost every convention error:

1. **Appendix Б** (`StandardExampleTests`): Б.1 and Б.2 — all intermediate values in hex. This is the only external
   reference for ONB.
2. **Reference X9.62 ONB multiplication** (`FieldTests.ReferenceOnbMultiply`) — 30 lines, ports as is.
3. **Squaring = cyclic shift right, unit = all ones** in ONB.
4. **Certificates** (`tests/UA.Cryptography.Tests/TestData/certificates`, `HistoricalCertificateTests`,
   `CzoTrustAnchorTests`): GOST 34.311 with a DKE and DSTU 7564 + point compression + signature verification on real
   data.
5. **GOST R 34.11-94 vectors** (`GostTests`), **DSTU 7564 examples** (`Dstu7564Tests`) and **DSTU 7624 vectors**
   (`Dstu7624Tests`, the JSON above).
6. **The curves of Г.1/Г.2 pass the checks of clause 8**, Г.2 = Г.1 after basis conversion (`BasisConverterTests`).

For PB, Java has a ready-made independent oracle — BouncyCastle (`org.bouncycastle.crypto.signers.DSTU4145Signer`,
`DSTU4145NamedCurves`); the C# tests are checked against the same library.

## Notes by language

- **Rust** — `u64`, hardware multiplication via `core::arch::aarch64::vmull_p64` / `x86_64::_mm_clmulepi64_si128`;
  big integers via `num-bigint` or `crypto-bigint` (the latter is constant time).
- **Go** — `uint64`, `math/bits` (`bits.Reverse64`); there is no built-in clmul without assembly, so use the portable
  4-bit window; big integers via `math/big`.
- **Java/Kotlin** — `long`, `Long.reverse`; no clmul (the JIT sometimes recognises the pattern), so use the portable
  variant; `BigInteger`.
- **TypeScript/JavaScript** — there are no 64-bit integers without `BigInt`; 32-bit words (`Uint32Array`) and a
  portable 32×32 → 64 multiplication built from two halves are more convenient; `BigInt` for numbers modulo n.
- **Python** — field elements can be stored as `int` (a bit mask), multiplication is shifts and XOR; slow, but very
  readable and handy as yet another independent reference.
