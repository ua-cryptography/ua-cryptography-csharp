using System.Numerics;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Cms;

/// <summary>A CMS attribute: its type and the values of its SET.</summary>
public sealed record CmsAttribute(string Oid, IReadOnlyList<Asn1Node> Values)
{
    public Asn1Node Value => Values.Count > 0 ? Values[0] : throw new InvalidDataException($"Attribute {Oid} has no value.");
}

/// <summary>
/// SignerInfo (RFC 5652, 5.3). The signer is identified by issuer and serial number or by subject key identifier; the
/// signature covers the DER SET OF the signed attributes (<see cref="SignedAttributesForSignature"/>), and for DSTU 4145
/// the signature field holds D directly, little-endian (docs/signature-formats.md, section 9).
/// </summary>
public sealed class SignerInfo
{
    internal SignerInfo(Asn1Node node)
    {
        Encoded = node.Encoded.ToArray();
        Version = node[0].GetInt32();
        Asn1Node sid = node[1];
        if (sid.Is(Asn1Tag.Sequence))
        {
            Issuer = DistinguishedName.FromAsn1(sid[0]);
            SerialNumber = sid[1].GetInteger();
        }
        else if (sid.IsContext(0))
        {
            SubjectKeyIdentifier = sid.GetOctetString();
        }
        DigestAlgorithm = node[2][0].GetOid();

        int i = 3;
        if (node[i].IsContext(0))
        {
            // [0] IMPLICIT SET OF Attribute: the signature is over the same bytes with the SET tag (RFC 5652, 5.4).
            byte[] attributes = node[i].Encoded.ToArray();
            attributes[0] = Asn1Tag.Set;
            SignedAttributesForSignature = attributes;
            SignedAttributes = ParseAttributes(node[i]);
            i++;
        }
        SignatureAlgorithm = node[i++][0].GetOid();
        Signature = node[i++].Expect(Asn1Tag.OctetString).GetOctetString();
        UnsignedAttributes = i < node.Count && node[i].IsContext(1) ? ParseAttributes(node[i]) : [];
    }

    public byte[] Encoded { get; }

    public int Version { get; }

    public DistinguishedName? Issuer { get; }

    public BigInteger? SerialNumber { get; }

    public byte[]? SubjectKeyIdentifier { get; }

    public string DigestAlgorithm { get; }

    /// <summary>The DER SET OF signed attributes as hashed for the signature, or null when there are none.</summary>
    public byte[]? SignedAttributesForSignature { get; }

    public IReadOnlyList<CmsAttribute> SignedAttributes { get; } = [];

    public string SignatureAlgorithm { get; }

    public byte[] Signature { get; }

    public IReadOnlyList<CmsAttribute> UnsignedAttributes { get; }

    public CmsAttribute? FindSigned(string oid) => SignedAttributes.FirstOrDefault(a => a.Oid == oid);

    public CmsAttribute? FindUnsigned(string oid) => UnsignedAttributes.FirstOrDefault(a => a.Oid == oid);

    /// <summary>True when the signer identifier names <paramref name="certificate"/>.</summary>
    public bool Identifies(Certificate certificate) => SubjectKeyIdentifier is not null
        ? certificate.SubjectKeyIdentifier is { } ski && ski.AsSpan().SequenceEqual(SubjectKeyIdentifier)
        : SerialNumber == certificate.SerialNumber && Issuer!.Equals(certificate.Issuer);

    public override string ToString() => SubjectKeyIdentifier is not null
        ? $"key identifier {Convert.ToHexString(SubjectKeyIdentifier)}"
        : $"serial number {SerialNumber:X} issued by {Issuer}";

    private static List<CmsAttribute> ParseAttributes(Asn1Node set) =>
        set.Children.Select(a => new CmsAttribute(a[0].GetOid(), a[1].Expect(Asn1Tag.Set).Children)).ToList();
}

/// <summary>ContentInfo with SignedData (RFC 5652, 5.1): the encapsulated content, the certificates and the signers.</summary>
public sealed class SignedData
{
    private SignedData(byte[] encoded)
    {
        Encoded = encoded;
        Asn1Node contentInfo = Asn1Node.Parse(encoded).Expect(Asn1Tag.Sequence);
        if (contentInfo[0].GetOid() != Oids.SignedData)
            throw new InvalidDataException("The CMS ContentInfo is not SignedData.");
        Asn1Node signedData = contentInfo[1].Expect(Asn1Tag.ContextConstructed(0))[0].Expect(Asn1Tag.Sequence);

        Version = signedData[0].GetInt32();
        DigestAlgorithms = signedData[1].Children.Select(a => a[0].GetOid()).ToList();
        Asn1Node encapsulated = signedData[2];
        ContentType = encapsulated[0].GetOid();
        Content = encapsulated.Count > 1 ? encapsulated[1].Expect(Asn1Tag.ContextConstructed(0))[0].GetOctetString() : null;

        var certificates = new List<Certificate>();
        int i = 3;
        if (signedData[i].IsContext(0))
        {
            foreach (Asn1Node choice in signedData[i].Children)
            {
                if (choice.Is(Asn1Tag.Sequence))
                    certificates.Add(Certificate.Load(choice.Encoded.Span)); // other CertificateChoices are skipped
            }
            i++;
        }
        if (signedData[i].IsContext(1))
            i++; // revocation information choices
        Certificates = certificates;
        SignerInfos = signedData[i].Expect(Asn1Tag.Set).Children.Select(s => new SignerInfo(s)).ToList();
    }

    /// <summary>Parses DER/BER, or PEM / bare base64 of it.</summary>
    public static SignedData Load(ReadOnlySpan<byte> data) => new(Pem.Decode(data, "CMS"));

    public byte[] Encoded { get; }

    public int Version { get; }

    public IReadOnlyList<string> DigestAlgorithms { get; }

    /// <summary>eContentType: <see cref="Oids.Data"/> for signatures, <see cref="Oids.TstInfo"/> for time-stamp tokens.</summary>
    public string ContentType { get; }

    /// <summary>The encapsulated content, or null for a detached signature.</summary>
    public byte[]? Content { get; }

    public IReadOnlyList<Certificate> Certificates { get; }

    public IReadOnlyList<SignerInfo> SignerInfos { get; }

    /// <summary>The certificate named by the signer identifier among the embedded ones and <paramref name="known"/>.</summary>
    public Certificate? FindCertificate(SignerInfo signer, IEnumerable<Certificate>? known = null) =>
        Certificates.Concat(known ?? []).FirstOrDefault(signer.Identifies);
}
