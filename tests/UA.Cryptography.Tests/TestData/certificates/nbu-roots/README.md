# NBU trust anchor

The self-signed DSTU 4145 root of the **National Bank of Ukraine's** certification centre
(Засвідчувальний центр НБУ). Qualified trust-service providers of banks — PrivatBank, for example — are certified
under this root rather than under a CZO root, so signatures made with keys issued by banks verify with it as `--trust`.

- **`nbu-root-2036-dstu7564.cer`** — `O=Національний банк України, CN=Засвідчувальний центр, SERIALNUMBER=UA-00032106-2611`,
  valid 2026-02-25 – 2036-02-24; m = 431 (polynomial basis); signature DSTU 4145 with DSTU 7564-256.
- **Source:** the certificate bundle PrivatBank publishes at the caIssuers address of its certificates,
  <http://acsk.privatbank.ua/arch/download/PB-2026-NBU.p7b>; the same certificate travels in its XAdES-B-LT signatures.
- **Nature:** a public certificate — no private data; safe to commit.

Its self-signature is verified by this library in `CzoTrustAnchorTests`, and `ChainToTrustAnchorTests` checks that
`../intermediates/privatbank-knedp.cer` chains to it.
