# Historical CA certificates (2005 – 2015)

Certificates of Ukrainian certification authorities, all expired, all public. They were collected in 2011 for the
DSTU 4145 extension of BouncyCastle C# and are the oldest real-world DSTU 4145 signatures available. Each one is
verified by this library with GOST 34.311 and the issuer's DKE (`HistoricalCertificateTests`).

| File | Subject | Issuer | Curve |
|---|---|---|---|
| `czo-root-2005.crt` | Central Certification Authority (ЦЗО), 2005 – 2010 | self-signed | m = 431, explicit parameters |
| `ucc-ca-2010.crt` | ТОВ «Український сертифікаційний центр» | `czo-root-2005.crt` | m = 431 |
| `ucc-tsp-2010.crt` | UCC time-stamping service | `ucc-ca-2010.crt` | m = 257 |
| `bitis-root-2009.crt` | CSK BITiS root | self-signed | m = 257, named curve |
| `bitis-corp-2009.crt` | CSK BITiS corporate CA | `bitis-root-2009.crt` | m = 257 |

Three different DKE (GOST 28147 substitution tables) occur among them; see `Gost/GostTests`.
