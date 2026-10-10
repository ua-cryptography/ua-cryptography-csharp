using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.X509;

/// <summary>keyUsage bits (RFC 5280, 4.2.1.3).</summary>
[Flags]
public enum KeyUsageFlags
{
    None = 0,
    DigitalSignature = 1 << 0,
    NonRepudiation = 1 << 1,
    KeyEncipherment = 1 << 2,
    DataEncipherment = 1 << 3,
    KeyAgreement = 1 << 4,
    KeyCertSign = 1 << 5,
    CrlSign = 1 << 6,
}

/// <summary>
/// Issues X.509 v3 certificates for DSTU 4145 keys, encoded by the conventions of the Ukrainian PKI
/// (docs/signature-formats.md, section 4): the signature value is a BIT STRING that wraps an OCTET STRING with D
/// (little-endian). Used for self-signed certificates of generated keys and for test hierarchies.
/// </summary>
public sealed class CertificateBuilder
{
    private readonly List<byte[]> _extensions = [];

    public CertificateBuilder(DistinguishedName subject, Dstu4145PublicKey publicKey)
    {
        Subject = subject;
        PublicKey = publicKey;
    }

    public DistinguishedName Subject { get; }

    public Dstu4145PublicKey PublicKey { get; }

    public DateTimeOffset NotBefore { get; set; } = DateTimeOffset.UtcNow.AddMinutes(-5);

    public DateTimeOffset NotAfter { get; set; } = DateTimeOffset.UtcNow.AddYears(1);

    /// <summary>A positive serial number; random 64 bits by default.</summary>
    public BigInteger SerialNumber { get; set; } = new BigInteger(RandomNumberGenerator.GetBytes(8), isUnsigned: true) | BigInteger.One;

    /// <summary>The signature algorithm: <see cref="Oids.Dstu4145WithDstu7564"/> (default) or <see cref="Oids.Dstu4145WithGost34311"/>.</summary>
    public string SignatureAlgorithm { get; set; } = Oids.Dstu4145WithDstu7564;

    public CertificateBuilder AddExtension(string oid, bool critical, byte[] value)
    {
        _extensions.Add(critical
            ? Der.Sequence(Der.ObjectIdentifier(oid), Der.Boolean(true), Der.OctetString(value))
            : Der.Sequence(Der.ObjectIdentifier(oid), Der.OctetString(value)));
        return this;
    }

    public CertificateBuilder AddBasicConstraints(bool isCa) =>
        AddExtension(Oids.BasicConstraints, critical: true, isCa ? Der.Sequence(Der.Boolean(true)) : Der.Sequence());

    public CertificateBuilder AddKeyUsage(KeyUsageFlags usage) => AddExtension(Oids.KeyUsage, critical: true, Der.NamedBits((int)usage));

    public CertificateBuilder AddExtendedKeyUsage(params string[] purposes) =>
        AddExtension(Oids.ExtendedKeyUsage, critical: true, Der.Sequence(purposes.Select(Der.ObjectIdentifier)));

    /// <summary>subjectKeyIdentifier: the DSTU 7564-256 hash of the public key bits (RFC 5280 leaves the method open).</summary>
    public CertificateBuilder AddSubjectKeyIdentifier() =>
        AddExtension(Oids.SubjectKeyIdentifier, critical: false, Der.OctetString(KeyIdentifier(PublicKey)));

    public CertificateBuilder AddAuthorityKeyIdentifier(byte[] keyIdentifier) =>
        AddExtension(Oids.AuthorityKeyIdentifier, critical: false, Der.Sequence(Der.Implicit(0, Der.OctetString(keyIdentifier))));

    /// <summary>authorityInfoAccess with OCSP and/or caIssuers URLs.</summary>
    public CertificateBuilder AddAuthorityInfoAccess(string? ocspUrl, string? caIssuersUrl = null)
    {
        var descriptions = new List<byte[]>();
        if (ocspUrl is not null)
            descriptions.Add(AccessDescription(Oids.AccessOcsp, ocspUrl));
        if (caIssuersUrl is not null)
            descriptions.Add(AccessDescription(Oids.AccessCaIssuers, caIssuersUrl));
        return AddExtension(Oids.AuthorityInfoAccess, critical: false, Der.Sequence(descriptions));
    }

    /// <summary>subjectInfoAccess with the time-stamping service URL.</summary>
    public CertificateBuilder AddTimeStampingUrl(string url) =>
        AddExtension(Oids.SubjectInfoAccess, critical: false, Der.Sequence(AccessDescription(Oids.AccessTimeStamping, url)));

    private static byte[] AccessDescription(string method, string url) =>
        Der.Sequence(Der.ObjectIdentifier(method), Der.Implicit(6, Der.Ia5String(url)));

    public static byte[] KeyIdentifier(Dstu4145PublicKey key)
    {
        byte[] bits = Der.Parse(key.ToSubjectPublicKeyInfo())[1].GetBitString();
        return PkiAlgorithms.Hash(Oids.Dstu7564_256, bits);
    }

    /// <summary>A certificate signed by its own key.</summary>
    public Certificate SelfSign(Dstu4145PrivateKey key) => Sign(Subject, key);

    /// <summary>A certificate issued by <paramref name="issuer"/> and signed by its key.</summary>
    public Certificate Issue(Certificate issuer, Dstu4145PrivateKey issuerKey) => Sign(issuer.Subject, issuerKey);

    private Certificate Sign(DistinguishedName issuer, Dstu4145PrivateKey signingKey)
    {
        byte[] algorithm = Der.AlgorithmIdentifier(SignatureAlgorithm);
        var tbs = new List<byte[]>
        {
            Der.Explicit(0, Der.Integer(2)),
            Der.Integer(SerialNumber),
            algorithm,
            issuer.Encoded,
            Der.Sequence(Der.Time(NotBefore), Der.Time(NotAfter)),
            Subject.Encoded,
            PublicKey.ToSubjectPublicKeyInfo(),
        };
        if (_extensions.Count > 0)
            tbs.Add(Der.Explicit(3, Der.Sequence(_extensions)));
        byte[] tbsEncoded = Der.Sequence(tbs);

        byte[] signature = signingKey.Sign(SignatureAlgorithm, tbsEncoded);
        return Certificate.Load(Der.Sequence(tbsEncoded, algorithm, Der.BitString(Der.OctetString(signature))));
    }
}
