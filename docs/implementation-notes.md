# Implementation notes

What you need to know to trust this implementation or to reproduce it: the errors and inaccuracies found in the text of
the standard, the conventions of the Ukrainian PKI, what verifies each layer, the state of the alternatives
(BouncyCastle), and how this library differs from the 2010 project it replaces.

## 1. Errors and inaccuracies in the text of DSTU 4145-2002

Found while checking the implementation against the examples of Appendix Б and against real data. The text of the
standard is not included in the repository (it is copyrighted by Derzhstandart of Ukraine); clauses are cited by
number.

1. **В.2, the condition for a type 2 ONB to exist.** The text says: "a) p′ ≡ 1 (mod 4) and k = 2m; b) p′ ≡ 3 (mod 4)
   and k = m". For **all** 14 degrees of table 2, p′ = 2m + 1 ≡ 3 (mod 4), and for m = 173, 233, 281, 293, 509 the order
   of two is k = 2m. Read literally, the text would mean that no ONB exists for them (including m = 173 of example Б.2).
   The correct condition: k = 2m (2 is a primitive root modulo p′) for any p′, or p′ ≡ 3 (mod 4) and k = m
   (`OptimalNormalBasisField.HasTypeTwoBasis`).
2. **В.8, the point addition formula.** The denominator of the second formula is printed as (x_P + y_Q); it must be
   (x_P + x_Q).
3. **Б.1, the coordinate x_Q.** One digit is missing from the printed value; the correct
   value `057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA` is confirmed by computing Q = −dP and by verifying the signature.
4. **Table Г.2 and the published base points.** The standard gives only (A, B, n); the base points were published by
   the cryptography.org.ua project (2010, "Рекомендованные кривые" — "Recommended curves", tables 2.1 and 2.2). For
   m = 179, 191, 431 the coefficient B there differs from table Г.2: it is B^(2^j) (a cyclic shift in the ONB) for
   j = 94, 190, 234 — the image of the curve under a power of the Frobenius map. Both curves are valid and isomorphic.
   The library uses B from Г.2 and maps the base points back, (x, y) → (x^(2^−j), y^(2^−j)); the test
   `PublishedOnbCurvesAreFrobeniusImagesOfTableG2` pins this down.
5. **Г.2 is Г.1 in the normal basis.** For all five common degrees (173, 179, 191, 233, 431), converting the curve of
   Г.1 to the ONB by В.6 (with a suitable root of the normal polynomial) gives exactly the coefficient B of Г.2. The
   orders n are the same. The published ONB base points are other generators of the same subgroup (not the images of
   the PB points).
6. **5.3, "the unit may be represented by the integer 1".** In the ONB the bit string of the unit is all ones, so this
   allowance is dangerous: the 2010 implementation fell into exactly this trap (section 5). The library maps A ∈ {0, 1}
   to the zero and the unit of the field, not to a bit string.
7. **6.9/6.10, compressing a point with x = 1.** If the standard representation of x_P is 1 (the least significant bit
   only) and tr(y_P/x_P) = 0, the compressed form is 0 — and by 6.10, 0 means the point (0, √B). Such a point can lie in
   the subgroup of order n (found for PB m = 163 and ONB m = 179), but its compression cannot be undone. The probability
   for a random key is ~2^−m; in this case the library throws in `Compress`.
8. Reference [10] (Montgomery, 1985) is multiplication modulo an integer; it does not apply directly to ONB
   multiplication. For curves over GF(2^m) the useful one is the "Montgomery ladder" (López–Dahab, 1999), which is used
   for kP.

## 2. Conventions of the Ukrainian PKI

In detail, format by format, in [signature-formats.md](signature-formats.md). In short:

- The signature algorithm of older certificates is OID `1.2.804.2.1.1.1.1.3.1.1` (DSTU 4145 with GOST 34.311, the "LE"
  variant); of newer ones, `1.2.804.2.1.1.1.1.3.6.1.1` (DSTU 4145 with DSTU 7564-256).
- The GOST 34.311 hash is computed with the S-box table from the DKE (64 bytes in the parameters of the issuer's key;
  without a DKE, DKE No. 1). The output of the hash function is **reversed** before 5.9 — for both GOST 34.311 and
  DSTU 7564 (BouncyCastle does the same for GOST in `Dstu4145Signer`; it does not implement the combination with
  DSTU 7564).
- The signature value D = S‖R of 5.10 is stored in **little-endian**: in certificates and OCSP responses in a
  `BIT STRING` wrapping an `OCTET STRING`, in CMS and timestamps directly in `SignerInfo.signature`, in XML as base64 in
  `ds:SignatureValue`.
- The public key is an `OCTET STRING` with the compressed point (6.9): little-endian for the key OID `…3.1.1`,
  big-endian for `…3.1.1.1.1`.
- The parameters are a named curve OID `1.2.804.2.1.1.1.1.3.1.1.2.i` (the i-th curve of table Г.1, i = 0…9) or an
  explicit structure `{ field (m, k | (k, j, l)), A, B (octets), n, base point (compressed, octets) }`, plus the DKE.
  Current certificates (ЦЗО, the "Дія" CA) give the curve explicitly, but the values match Г.1 together with the base
  point; the 2005 ЦЗО root used m = 431 with a different base point.
- DKEs seen in the wild: "DKE No. 1" `A9D6EB45…` (the default, same as BouncyCastle), `4A92D80E…` (UCC, УСЦ; this is
  the "test" set of GOST R 34.11-94), `8BC217ED…` (ЦЗО 2005).
- All conventions were established on real data: five CA certificates from 2005–2015, the ЦЗО roots and the
  certificate of the "Дія" CA (they are in `tests/UA.Cryptography.Tests/TestData/certificates`), and qualified XAdES,
  CAdES and PAdES signatures made with the "Дія" qualified signature tools (not included in the repository because they
  contain personal data). Changing one byte of the data or of the signature gives "invalid" in every case.

## 3. What verifies each layer

Every level is checked by at least one independent source:

| What | Verified by |
|---|---|
| Polynomial multiplication (hardware and portable) | Naive bitwise multiplication; the hardware path against the portable one |
| PB field | Field axioms, a^(2^m) = a, inversion, trace by the definition of 6.5, half-trace — for all 60 polynomials of table 1; irreducibility of all polynomials of table 1; BouncyCastle |
| ONB field | Reference ANSI X9.62 / IEEE 1363 multiplication (written from scratch in the tests), exhaustive products of basis elements over small fields, "squaring = cyclic shift right", "unit = all ones", axioms for all 14 degrees of table 2 |
| PB ↔ ONB conversion | Field isomorphism; the normal element found is a root of the normal polynomial of В.2; kP commutes with the conversion |
| Curve and kP | The ladder against affine double-and-add by В.8; edge values of k (0, 1, 2, 3, n − 1, n, n + 1, negative); group laws; point compression; BouncyCastle (PB) |
| Signature | Appendix Б (Б.1 and Б.2) value by value; mutual verification of signatures with BouncyCastle (PB); real certificates (PB, m = 257, 431; GOST 34.311 and DSTU 7564) |
| Parameters | All 15 recommended curves pass the checks of clause 8 (including Miller–Rabin and the MOV condition); the 10 curves of Г.1 match BouncyCastle together with the base points |
| GOST 28147 / 34.311 | BouncyCastle with four S-box tables (3 DKEs from certificates + CryptoPro); the published GOST R 34.11-94 vectors |
| DSTU 7564 | 17 test examples from the standard and the Kupyna paper; BouncyCastle at lengths around the block and length-field boundaries |
| DSTU 7624 | Test examples of the standard for all modes; 590 vectors from BouncyCastle Java 1.86 (`tools/dstu7624-vectors`) |
| Signature formats | The synthetic PKI mirrors the national chain; XAdES, ASiC-E, CAdES (B, T, X Long), ASiC-S, PAdES (B, LTA), RFC 3161 timestamps and OCSP are verified by the same functions that accept the real certificates; BouncyCastle confirms the structure of timestamps and OCSP |

## 4. Alternatives: what BouncyCastle can do

Checked in October 2026 on the latest versions: C# 2.7.0, Java 1.86.

- **DSTU 4145 in the polynomial basis** is built in (`Org.BouncyCastle.Asn1.UA`, `Dstu4145Signer`, the 10 curves of
  Г.1). But BouncyCastle C# does **not** verify Ukrainian certificates by itself ("Signing mechanism
  1.2.804.2.1.1.1.1.3.1.1 not recognised"), and it does not know the DSTU 4145 + DSTU 7564 combination at all.
- **There is no normal basis** in any version. `F2mFieldElement` (C#) / `ECFieldElement.F2m` (Java) declare the
  constant `Gnb = 1` ("Gaussian normal basis"), but the Java code next to it says plainly "GNB is not implemented at
  present"; `F2mCurve` can only be created from a trinomial or a pentanomial, there are no Г.2 curves, and the ASN.1
  structure `DSTU4145BinaryField` only supports (m, k) and (m, k, j, l). That is why the ONB tests use an independent
  reference implementation of X9.62 and basis conversion from PB.
- **DSTU 7624 (Kalyna).** Java 1.86 has the full set: the cipher, KCTR, KCCM, KGCM, KGMac, KXTS, CMAC (`DSTU7624Mac`),
  key wrapping, plus the generic ECB/CBC/CFB/OFB. C# 2.7.0 lacks GCM, GMAC and XTS, and `KCcmBlockCipher` accepts AAD
  and data in whole blocks only; within these limits the results match Java. That is why the library ports the Java
  version (`src/UA.Cryptography/Dstu7624`), and the reference vectors for the tests come from running BouncyCastle Java.

## 5. Differences from the 2010 project

This library is written from scratch and replaces the implementation of the cryptography.org.ua project of 2010–2011
(C#, .NET Framework 4.0, polynomial and normal bases). None of that project's code was carried over; below is what was
wrong with it. This matters if you need to check signatures made by the old library: they are **not compatible** with
the standard.

**Polynomial basis.**

1. The truncation of 5.8 was not performed: `r = h·F_e` was taken whole, without truncating it to L(n) − 1 bits, and
   verification also compared untruncated values. The signature is self-consistent but incompatible with the standard
   and with other implementations.
2. 5.9–5.11 were missing: the hash was passed directly as a number, there was no D = S‖R encoding; h = 0, r = 0 and
   s = 0 were not handled; verification lacked the conditions 0 < r < n, 0 < s < n.
3. Random numbers were built through a signed binary string: the distribution is biased, whereas 6.3 requires at most
   L(n) − 1 bits; the private key and e could end up ≥ n or zero.
4. The quadratic equation of 6.7 was solved without the cases u = 0, w = 0 and tr(v) = 1.
5. Point multiplication was double-and-add in affine coordinates with an inversion at every step; the addition was
   done only for the one bits of the secret scalar.

**Normal basis.**

1. Field multiplication computed each bit of the product separately by the matrix of В.4: 217 µs per multiplication at
   m = 173 (55 ns here), seconds per signature.
2. Only the m = 173 curve worked: the coefficient A = 1 was given as the bit string 00…01, i.e. a basis element rather
   than the unit of the field (all ones, 5.3). The Г.2 curve for m = 173 has A = 0, so everything matched there. The
   field arithmetic itself was correct for all degrees (checked against the new implementation).
3. `Point.Equals` always returned `false` for finite points, so P + P never went to doubling; the point at infinity
   was confused with the point x = 1; with tr(v) = 1 in 6.7 an exception was thrown instead of picking a new point.
4. The signature had the same problems as in PB (no 5.8–5.11).

## 6. Possible next steps

- An ASN.1/X.509/CMS layer for keys, certificates and signed documents (conventions in
  [signature-formats.md](signature-formats.md); the verification recipes already exist in the tests,
  `tests/UA.Cryptography.Tests/Support/UaPki.cs`).
- Key containers: JKS (the format is pinned down in the tests), PKCS#12, IIT containers.
- Faster signing: precomputation for the fixed base point (comb/window) makes kP for eP several times faster; in
  verification, joint computation of sP + rQ (Shamir's trick).
- Faster field arithmetic: Karatsuba for m ≥ 300, specialised reduction for trinomials.
- Side-channel protection: constant time for arithmetic modulo n and for the portable multiplication.
- Ports to other languages — see [porting.md](porting.md).
