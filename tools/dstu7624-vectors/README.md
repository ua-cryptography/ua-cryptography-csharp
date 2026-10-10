# DSTU 7624 reference vectors from BouncyCastle Java

`GenerateVectors.java` runs every Kalyna mode in BouncyCastle Java 1.86 and writes the results to
`tests/UA.Cryptography.Tests/TestData/vectors/dstu7624-bc-java-1.86.json`; the C# translation
(`src/UA.Cryptography/Dstu7624`) is checked against them in `Dstu7624Tests.MatchesBouncyCastleJava`.

```bash
curl -LO https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar
# SHA-1 830c8467bed8e4c1148262386b09fc42aedcf262
javac -cp bcprov-jdk18on-1.86.jar GenerateVectors.java
java -cp bcprov-jdk18on-1.86.jar:. GenerateVectors ../../tests/UA.Cryptography.Tests/TestData/vectors/dstu7624-bc-java-1.86.json
```

The input data is deterministic (`new Random(7624)`), so running it again produces the same file.
