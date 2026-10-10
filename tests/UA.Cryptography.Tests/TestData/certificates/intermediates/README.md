# Intermediate CA certificates

Public intermediate (issuing) CA certificates of the national PKI, used to build chains up to the trusted CZO roots in
`../czo-roots/`.

- **`dia-knedp.cer`** — `"Дія". Кваліфікований надавач електронних довірчих послуг` (ДП «ДІЯ»), the qualified
  trust-service provider behind Diia e-signatures. Issued by `czo-root-2036-dstu7564.cer`; signature DSTU 4145 with
  DSTU 7564-256. Extracted from the official bundle <https://czo.gov.ua/download/certificates/CACertificates.p7b>.

`ChainToTrustAnchorTests` verifies that this certificate chains to a trusted CZO root.
