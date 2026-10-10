using System.Numerics;
using System.Text;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.X509;

/// <summary>An X.509 v3 extension: its OID, criticality and the DER value inside the OCTET STRING.</summary>
public sealed record CertificateExtension(string Oid, bool Critical, byte[] Value);

/// <summary>
/// An X.509 certificate (RFC 5280) parsed by this package's DER reader. The DSTU 4145 key is decoded on first use,
/// so certificates with other key types can still be parsed, listed and matched.
/// </summary>
public sealed class Certificate : IEquatable<Certificate>
{
    private Dstu4145PublicKey? _publicKey;

    private Certificate(byte[] encoded)
    {
        Encoded = encoded;
        Asn1Node certificate = Asn1Node.Parse(encoded).Expect(Asn1Tag.Sequence);
        Asn1Node tbs = certificate[0].Expect(Asn1Tag.Sequence);
        TbsEncoded = tbs.Encoded.ToArray();
        SignatureAlgorithm = certificate[1][0].GetOid();
        SignatureValue = certificate[2].GetBitString();

        int i = 0;
        if (tbs[0].IsContext(0))
        {
            Version = tbs[0][0].GetInt32() + 1;
            i++;
        }
        else
        {
            Version = 1;
        }
        SerialNumber = tbs[i++].GetInteger();
        i++; // signature AlgorithmIdentifier, repeated from the outer structure
        Issuer = DistinguishedName.FromAsn1(tbs[i++]);
        Asn1Node validity = tbs[i++];
        NotBefore = validity[0].GetTime();
        NotAfter = validity[1].GetTime();
        Subject = DistinguishedName.FromAsn1(tbs[i++]);
        Asn1Node spki = tbs[i++].Expect(Asn1Tag.Sequence);
        SubjectPublicKeyInfo = spki.Encoded.ToArray();
        PublicKeyAlgorithm = spki[0][0].GetOid();
        PublicKeyBits = spki[1].GetBitString();

        var extensions = new List<CertificateExtension>();
        for (; i < tbs.Count; i++)
        {
            if (!tbs[i].IsContext(3))
                continue; // issuerUniqueID [1], subjectUniqueID [2]
            foreach (Asn1Node extension in tbs[i][0].Expect(Asn1Tag.Sequence).Children)
            {
                bool critical = extension.Count == 3 && extension[1].GetBoolean();
                extensions.Add(new CertificateExtension(extension[0].GetOid(), critical, extension[^1].GetOctetString()));
            }
        }
        Extensions = extensions;
    }

    /// <summary>Parses a DER certificate, or PEM / bare base64 text holding one.</summary>
    public static Certificate Load(ReadOnlySpan<byte> data) => new(Pem.Decode(data, "CERTIFICATE"));

    public static Certificate Load(string path) => Load(File.ReadAllBytes(path));

    public byte[] Encoded { get; }

    /// <summary>The DER TBSCertificate, the bytes covered by the signature.</summary>
    public byte[] TbsEncoded { get; }

    public int Version { get; }

    public BigInteger SerialNumber { get; }

    public DistinguishedName Issuer { get; }

    public DistinguishedName Subject { get; }

    public DateTimeOffset NotBefore { get; }

    public DateTimeOffset NotAfter { get; }

    public string SignatureAlgorithm { get; }

    /// <summary>The signatureValue BIT STRING (for DSTU 4145, a DER OCTET STRING with D, little-endian).</summary>
    public byte[] SignatureValue { get; }

    public byte[] SubjectPublicKeyInfo { get; }

    public string PublicKeyAlgorithm { get; }

    /// <summary>The subjectPublicKey BIT STRING value (what OCSP CertID's issuerKeyHash covers).</summary>
    public byte[] PublicKeyBits { get; }

    public IReadOnlyList<CertificateExtension> Extensions { get; }

    public bool HasDstu4145Key => Dstu4145PublicKey.IsDstu4145(PublicKeyAlgorithm);

    /// <summary>The DSTU 4145 key, checked by section 8 (parameters) and 10.1 (point).</summary>
    public Dstu4145PublicKey PublicKey => _publicKey ??= HasDstu4145Key
        ? Dstu4145PublicKey.FromSubjectPublicKeyInfo(Asn1Node.Parse(SubjectPublicKeyInfo))
        : throw new NotSupportedException($"The key of '{Subject}' is not a DSTU 4145 key ({PublicKeyAlgorithm}).");

    public bool IsSelfIssued => Subject.Equals(Issuer);

    public CertificateExtension? FindExtension(string oid) => Extensions.FirstOrDefault(e => e.Oid == oid);

    /// <summary>basicConstraints cA (RFC 5280, 4.2.1.9).</summary>
    public bool IsCa
    {
        get
        {
            CertificateExtension? e = FindExtension(Oids.BasicConstraints);
            if (e is null)
                return false;
            Asn1Node sequence = Asn1Node.Parse(e.Value);
            return sequence.Count > 0 && sequence[0].Is(Asn1Tag.Boolean) && sequence[0].GetBoolean();
        }
    }

    /// <summary>keyUsage bits (RFC 5280, 4.2.1.3; bit 0 digitalSignature, 1 nonRepudiation, 5 keyCertSign), or null when absent.</summary>
    public int? KeyUsage => FindExtension(Oids.KeyUsage) is { } e ? Asn1Node.Parse(e.Value).GetNamedBits() : null;

    public IReadOnlyList<string> ExtendedKeyUsage => FindExtension(Oids.ExtendedKeyUsage) is { } e
        ? Asn1Node.Parse(e.Value).Children.Select(c => c.GetOid()).ToList()
        : [];

    public byte[]? SubjectKeyIdentifier => FindExtension(Oids.SubjectKeyIdentifier) is { } e
        ? Asn1Node.Parse(e.Value).Expect(Asn1Tag.OctetString).GetOctetString()
        : null;

    public byte[]? AuthorityKeyIdentifier
    {
        get
        {
            if (FindExtension(Oids.AuthorityKeyIdentifier) is not { } e)
                return null;
            Asn1Node? keyId = Asn1Node.Parse(e.Value).Children.FirstOrDefault(c => c.IsContext(0));
            return keyId?.GetOctetString();
        }
    }

    /// <summary>OCSP responder URLs (authorityInfoAccess, id-ad-ocsp).</summary>
    public IReadOnlyList<string> OcspUrls => AccessUrls(Oids.AuthorityInfoAccess, Oids.AccessOcsp);

    /// <summary>Where the issuer's certificate can be downloaded (authorityInfoAccess, id-ad-caIssuers).</summary>
    public IReadOnlyList<string> CaIssuerUrls => AccessUrls(Oids.AuthorityInfoAccess, Oids.AccessCaIssuers);

    /// <summary>The time-stamping service of the CA (subjectInfoAccess, id-ad-timeStamping), as Ukrainian CAs publish it.</summary>
    public IReadOnlyList<string> TimeStampUrls => AccessUrls(Oids.SubjectInfoAccess, Oids.AccessTimeStamping);

    private List<string> AccessUrls(string extension, string method)
    {
        if (FindExtension(extension) is not { } e)
            return [];
        var urls = new List<string>();
        foreach (Asn1Node description in Asn1Node.Parse(e.Value).Children)
        {
            Asn1Node location = description[1];
            if (description[0].GetOid() == method && location.IsContext(6) && !location.IsConstructed)
                urls.Add(Encoding.ASCII.GetString(location.Content.Span)); // uniformResourceIdentifier [6] IA5String
        }
        return urls;
    }

    /// <summary>
    /// Verifies this certificate's signature with the issuer's key (section 4): the hash comes from the signature
    /// algorithm, GOST 34.311 uses the issuer's DKE.
    /// </summary>
    public bool IsSignedBy(Certificate issuer)
    {
        try
        {
            byte[] d = Asn1Node.Parse(SignatureValue).Expect(Asn1Tag.OctetString).GetOctetString();
            return issuer.HasDstu4145Key && issuer.PublicKey.Verify(SignatureAlgorithm, TbsEncoded, d);
        }
        catch (Exception e) when (e is InvalidDataException or NotSupportedException or ArgumentException)
        {
            return false;
        }
    }

    public bool IsValidAt(DateTimeOffset time) => time >= NotBefore && time <= NotAfter;

    public bool Equals(Certificate? other) => other is not null && Encoded.AsSpan().SequenceEqual(other.Encoded);

    public override bool Equals(object? obj) => obj is Certificate c && Equals(c);

    public override int GetHashCode() => SerialNumber.GetHashCode();

    public override string ToString() => Subject.ToString();
}
