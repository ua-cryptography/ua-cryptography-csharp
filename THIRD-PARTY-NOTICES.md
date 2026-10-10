# Third-party notices

## BouncyCastle (Java)

`src/UA.Cryptography/Dstu7624/` is a C# translation of the DSTU 7624 ("Kalyna") classes of BouncyCastle Java 1.86
(`bcprov-jdk18on`): `DSTU7624Engine`, `DSTU7624WrapEngine`, `DSTU7624Mac`, `KGMac`, `KCTRBlockCipher`,
`KCCMBlockCipher`, `KGCMBlockCipher`, `KXTSBlockCipher`; each file names the class it was translated from. The S-box tables in `src/UA.Cryptography/Common/DstuSBoxes.cs`
(shared with DSTU 7564) were taken from the same library; they are the tables of the standards.
`tools/dstu7624-vectors/GenerateVectors.java` uses BouncyCastle Java to produce reference test vectors.

MIT License (https://opensource.org/licenses/MIT)

Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

## cryptography.org.ua (2010 – 2011)

The base points of the recommended curves in `src/UA.Cryptography/Dstu4145/Dstu4145NamedCurves.cs` (DSTU 4145-2002
lists only A, B and n) are the ones published by the Ukrainian open-source project at http://cryptography.org.ua
("Рекомендованные кривые", tables 2.1 and 2.2); the authors are listed at http://web.cryptography.org.ua/authors.html.
That project's code was distributed under the BSD licence with the requirement to credit the project and its authors.
No code of that project is included here: this library is a new implementation.

The historical CA certificates in `tests/UA.Cryptography.Tests/TestData/certificates/historical/` were collected by the
same project in 2011. They are public certificates of Ukrainian certification authorities.

