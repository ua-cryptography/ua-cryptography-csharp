using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Cms;

/// <summary>
/// Builds CMS SignedData with one DSTU 4145 signer, shared by CAdES signatures and time-stamp tokens. The signed
/// attributes are contentType, messageDigest and signingCertificateV2 plus any extra ones; the signature covers their
/// DER SET OF, and SignerInfo.signature holds D little-endian (docs/signature-formats.md, section 9).
/// </summary>
public static class CmsBuilder
{
    /// <summary>An Attribute ::= SEQUENCE { attrType, SET OF value }.</summary>
    public static byte[] Attribute(string oid, params byte[][] values) => Der.Sequence(Der.ObjectIdentifier(oid), Der.SetOf(values));

    /// <summary>
    /// signingCertificateV2 (RFC 5035): one ESSCertIDv2 with the hash of the certificate, the algorithm written out, and
    /// issuerSerial — the issuer as a directoryName and the serial number — as IIT and the banks write it.
    /// </summary>
    public static byte[] SigningCertificateV2(Certificate certificate, string hashOid) =>
        Attribute(Oids.SigningCertificateV2, Der.Sequence(Der.Sequence(Der.Sequence(
            Der.AlgorithmIdentifier(hashOid),
            Der.OctetString(PkiAlgorithms.Hash(hashOid, certificate.Encoded)),
            IssuerSerial(certificate)))));

    /// <summary>IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber }, the issuer as GeneralName directoryName [4].</summary>
    public static byte[] IssuerSerial(Certificate certificate) =>
        Der.Sequence(Der.Sequence(Der.Explicit(4, certificate.Issuer.Encoded)), Der.Integer(certificate.SerialNumber));

    /// <summary>
    /// The DER SET OF signed attributes for <paramref name="content"/>: contentType, the extra attributes, messageDigest and
    /// signingCertificateV2. The hash of GOST 34.311 uses the signer's DKE.
    /// </summary>
    public static byte[] SignedAttributes(byte[] content, string contentType, SigningKey signer, string hashOid, IEnumerable<byte[]>? extra = null)
    {
        byte[][] attributes =
        [
            Attribute(Oids.ContentType, Der.ObjectIdentifier(contentType)),
            .. extra ?? [],
            Attribute(Oids.MessageDigest, Der.OctetString(PkiAlgorithms.Hash(hashOid, content, signer.Key.Dke))),
            SigningCertificateV2(signer.Certificate, hashOid),
        ];
        return Der.SetOf(attributes);
    }

    /// <summary>SignerInfo version 1 with issuerAndSerialNumber, signing <paramref name="signedAttributes"/> (a DER SET).</summary>
    public static (byte[] SignerInfo, byte[] Signature) SignerInfo(byte[] signedAttributes, SigningKey signer, string hashOid,
        IEnumerable<byte[]>? unsignedAttributes = null)
    {
        byte[] signature = signer.Key.SignHash(PkiAlgorithms.Hash(hashOid, signedAttributes, signer.Key.Dke));
        return (SignerInfoWith(signedAttributes, signature, signer.Certificate, hashOid, unsignedAttributes), signature);
    }

    /// <summary>The same SignerInfo fields with a given signature value and unsigned attributes.</summary>
    public static byte[] SignerInfoWith(byte[] signedAttributes, byte[] signature, Certificate certificate, string hashOid,
        IEnumerable<byte[]>? unsignedAttributes = null)
    {
        var fields = new List<byte[]>
        {
            Der.Integer(1),
            Der.Sequence(certificate.Issuer.Encoded, Der.Integer(certificate.SerialNumber)),
            Der.AlgorithmIdentifier(hashOid),
            Der.Implicit(0, signedAttributes),
            Der.AlgorithmIdentifier(PkiAlgorithms.SignatureAlgorithmFor(hashOid)),
            Der.OctetString(signature),
        };
        List<byte[]> unsigned = unsignedAttributes?.ToList() ?? [];
        if (unsigned.Count > 0)
            fields.Add(Der.Implicit(1, Der.SetOf(unsigned)));
        return Der.Sequence(fields);
    }

    /// <summary>ContentInfo { SignedData } with one signer; the content is encapsulated unless <paramref name="encapsulated"/> is null.</summary>
    public static byte[] SignedData(byte[] signerInfo, string hashOid, string contentType, byte[]? encapsulated, IEnumerable<Certificate> certificates)
    {
        byte[] encapContentInfo = encapsulated is null
            ? Der.Sequence(Der.ObjectIdentifier(contentType))
            : Der.Sequence(Der.ObjectIdentifier(contentType), Der.Explicit(0, Der.OctetString(encapsulated)));
        var fields = new List<byte[]>
        {
            Der.Integer(contentType == Oids.Data ? 1 : 3),
            Der.SetOf(Der.AlgorithmIdentifier(hashOid)),
            encapContentInfo,
        };
        List<Certificate> list = certificates.Distinct().ToList();
        if (list.Count > 0)
            fields.Add(Der.Implicit(0, Der.SetOf(list.Select(c => c.Encoded))));
        fields.Add(Der.SetOf(signerInfo));
        return Der.Sequence(Der.ObjectIdentifier(Oids.SignedData), Der.Explicit(0, Der.Sequence(fields)));
    }
}
