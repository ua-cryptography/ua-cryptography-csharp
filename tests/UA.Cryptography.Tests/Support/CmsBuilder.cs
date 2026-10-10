using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.X509;
using AttributeCms = Org.BouncyCastle.Asn1.Cms.Attribute;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// CMS SignedData with one DSTU 4145 signer, shared by CAdES signatures and time-stamp tokens. The signed attributes
/// are contentType, messageDigest and signingCertificateV2 (plus any extra ones); the signature covers their DER
/// SET OF and the SignerInfo holds D directly, little-endian (docs/signature-formats.md, section 9).
/// </summary>
internal static class CmsBuilder
{
    public static SignerInfo CreateSignerInfo(byte[] content, DerObjectIdentifier contentType, TestPki.TestIdentity signer,
        string hashOid, IEnumerable<AttributeCms>? extraSignedAttributes = null)
    {
        var digestAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier(hashOid));
        var essCertId = new EssCertIDv2(digestAlgorithm, UaPki.Hash(hashOid, signer.Certificate.GetEncoded()));
        AttributeCms[] signedAttributes =
        [
            new(PkcsObjectIdentifiers.Pkcs9AtContentType, new DerSet(contentType)),
            .. extraSignedAttributes ?? [],
            new(PkcsObjectIdentifiers.Pkcs9AtMessageDigest, new DerSet(new DerOctetString(UaPki.Hash(hashOid, content)))),
            new(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(new SigningCertificateV2([essCertId]))),
        ];
        var attributes = new DerSet(signedAttributes);
        byte[] signature = TestPki.SignHash(signer.Key, UaPki.Hash(hashOid, attributes.GetEncoded(Asn1Encodable.Der)));

        return new SignerInfo(
            new SignerIdentifier(new IssuerAndSerialNumber(signer.Certificate.CertificateStructure)),
            digestAlgorithm,
            attributes,
            new AlgorithmIdentifier(new DerObjectIdentifier(UaPki.SignatureAlgorithmFor(hashOid))),
            new DerOctetString(signature),
            null);
    }

    /// <summary>The same SignerInfo with unsigned attributes added (they are outside the signature).</summary>
    public static SignerInfo WithUnsignedAttributes(SignerInfo signerInfo, IEnumerable<AttributeCms> attributes)
    {
        IEnumerable<Asn1Encodable> existing = signerInfo.UnsignedAttrs?.Cast<Asn1Encodable>() ?? [];
        return new SignerInfo(signerInfo.SignerID, signerInfo.DigestAlgorithm, signerInfo.SignedAttrs,
            signerInfo.SignatureAlgorithm, signerInfo.Signature, new DerSet(existing.Concat(attributes).ToArray()));
    }

    /// <summary>ContentInfo { SignedData }; the content is encapsulated when <paramref name="encapsulated"/> is given.</summary>
    public static ContentInfo SignedData(SignerInfo signerInfo, DerObjectIdentifier contentType, byte[]? encapsulated,
        IEnumerable<X509Certificate> certificates)
    {
        var signedData = new SignedData(
            new DerSet(signerInfo.DigestAlgorithm),
            new ContentInfo(contentType, encapsulated is null ? null : new DerOctetString(encapsulated)),
            new DerSet(certificates.Select(c => (Asn1Encodable)c.CertificateStructure).ToArray()),
            null,
            new DerSet(signerInfo));
        return new ContentInfo(CmsObjectIdentifiers.SignedData, signedData);
    }

    public static ContentInfo Sign(byte[] content, DerObjectIdentifier contentType, bool encapsulate, TestPki.TestIdentity signer,
        IEnumerable<X509Certificate> certificates, string hashOid) =>
        SignedData(CreateSignerInfo(content, contentType, signer, hashOid), contentType, encapsulate ? content : null, certificates);
}
