# Intermediate CA certificates

Public intermediate (issuing) CA certificates of the national PKI, used to build chains up to the trusted roots in
`../czo-roots/` and `../nbu-roots/`.

- **`dia-knedp.cer`** — `"Дія". Кваліфікований надавач електронних довірчих послуг` (ДП «ДІЯ»), the qualified
  trust-service provider behind Diia e-signatures. Issued by `czo-root-2036-dstu7564.cer`; signature DSTU 4145 with
  DSTU 7564-256. Extracted from the official bundle <https://czo.gov.ua/download/certificates/CACertificates.p7b>.

- **`privatbank-knedp.cer`** — `КНЕДП АЦСК АТ КБ "ПриватБанк"` (`SERIALNUMBER=UA-14360570-2610`), the qualified
  trust-service provider of PrivatBank. Issued by `../nbu-roots/nbu-root-2036-dstu7564.cer`; signature DSTU 4145 with
  DSTU 7564-256. Taken from the bundle at its certificates' caIssuers address,
  <http://acsk.privatbank.ua/arch/download/PB-2026-NBU.p7b>.

`ChainToTrustAnchorTests` verifies that each certificate chains to its trusted root.
