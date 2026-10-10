using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Gost;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BigInteger = System.Numerics.BigInteger;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// Synthetic PKI generator for the tests: DSTU 4145 keys and certificates made entirely with this library's crypto,
/// encoded by the conventions of the Ukrainian PKI (docs/signature-formats.md). BouncyCastle only assembles the
/// ASN.1. Nothing here depends on personal data; everything is generated on the fly.
/// </summary>
internal static class TestPki
{
    /// <summary>A generated key together with its domain parameters, public key and GOST 34.311 DKE.</summary>
    public sealed record TestKey(Dstu4145DomainParameters Domain, BigInteger PrivateKey, CurvePoint PublicKey, byte[] Dke)
    {
        public int M => Domain.Field.M;
    }

    /// <summary>A key plus the certificate that certifies it.</summary>
    public sealed record TestIdentity(TestKey Key, X509Certificate Certificate);

    /// <summary>Generates a fresh DSTU 4145 key on the named polynomial-basis curve of degree <paramref name="m"/>.</summary>
    public static TestKey GenerateKey(int m = 257)
    {
        Dstu4145DomainParameters domain = Dstu4145NamedCurves.Polynomial(m);
        Dstu4145KeyPair pair = new Dstu4145Signer(domain).GenerateKeyPair();
        return new TestKey(domain, pair.PrivateKey, pair.PublicKey, Gost34311.DefaultDke.ToArray());
    }

    /// <summary>A self-signed certificate (issuer = subject), suitable for a test root CA or a standalone key.</summary>
    public static TestIdentity CreateSelfSigned(string subjectDn, TestKey? key = null, bool isCa = true,
        string signatureAlgorithm = Oids.Dstu4145WithGost34311)
    {
        key ??= GenerateKey();
        var subject = new X509Name(subjectDn);
        return new TestIdentity(key, BuildCertificate(subject, key, subject, key, isCa, null, signatureAlgorithm));
    }

    /// <summary>A certificate for <paramref name="subjectKey"/> issued and signed by <paramref name="issuer"/>.</summary>
    public static TestIdentity Issue(string subjectDn, TestKey subjectKey, TestIdentity issuer, bool isCa = false,
        KeyPurposeID? extendedKeyUsage = null, string signatureAlgorithm = Oids.Dstu4145WithGost34311)
    {
        X509Certificate certificate = BuildCertificate(new X509Name(subjectDn), subjectKey, issuer.Certificate.SubjectDN, issuer.Key,
            isCa, extendedKeyUsage, signatureAlgorithm);
        return new TestIdentity(subjectKey, certificate);
    }

    // ---- X.509 ----------------------------------------------------------------------------------------------

    /// <summary>The named-curve OID for a polynomial-basis degree, e.g. m = 257 → …3.1.1.2.6.</summary>
    public static DerObjectIdentifier NamedCurveOid(int m)
    {
        int index = Dstu4145NamedCurves.PolynomialDegrees.ToList().IndexOf(m);
        if (index < 0)
            throw new ArgumentException($"No named polynomial curve of degree {m}.", nameof(m));
        return new DerObjectIdentifier(Oids.NamedCurvePrefix + index);
    }

    /// <summary>AlgorithmIdentifier for a DSTU 4145 key: the little-endian OID with { namedCurve, DKE } parameters.</summary>
    public static AlgorithmIdentifier KeyAlgorithmIdentifier(TestKey key) =>
        new(new DerObjectIdentifier(Oids.Dstu4145Le), new DerSequence(NamedCurveOid(key.M), new DerOctetString(key.Dke)));

    /// <summary>SubjectPublicKeyInfo: the compressed public key point, little-endian, in an OCTET STRING in the BIT STRING.</summary>
    public static SubjectPublicKeyInfo BuildSpki(TestKey key)
    {
        BigInteger compressed = key.Domain.Curve.Compress(key.PublicKey);
        byte[] littleEndian = ToFixedLittleEndian(compressed, (key.M + 7) / 8);
        return new SubjectPublicKeyInfo(KeyAlgorithmIdentifier(key), new DerOctetString(littleEndian));
    }

    private static X509Certificate BuildCertificate(X509Name subject, TestKey subjectKey, X509Name issuer, TestKey issuerKey,
        bool isCa, KeyPurposeID? extendedKeyUsage, string signatureAlgorithm)
    {
        var algorithm = new AlgorithmIdentifier(new DerObjectIdentifier(signatureAlgorithm));
        var gen = new V3TbsCertificateGenerator();
        gen.SetSerialNumber(new DerInteger(BcBigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue))));
        gen.SetIssuer(issuer);
        gen.SetSubject(subject);
        gen.SetStartDate(new Time(DateTime.UtcNow.AddDays(-1)));
        gen.SetEndDate(new Time(DateTime.UtcNow.AddYears(5)));
        gen.SetSignature(algorithm);
        gen.SetSubjectPublicKeyInfo(BuildSpki(subjectKey));

        var extensions = new X509ExtensionsGenerator();
        extensions.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(isCa));
        if (extendedKeyUsage is not null)
            extensions.AddExtension(X509Extensions.ExtendedKeyUsage, critical: true, new ExtendedKeyUsage(extendedKeyUsage));
        gen.SetExtensions(extensions.Generate());

        TbsCertificateStructure tbs = gen.GenerateTbsCertificate();
        byte[] signature = Sign(issuerKey, tbs.GetDerEncoded(), signatureAlgorithm);
        // The certificate signature is a BIT STRING that wraps an OCTET STRING holding D (little-endian).
        var signatureBits = new DerBitString(new DerOctetString(signature).GetDerEncoded());
        return new X509Certificate(X509CertificateStructure.GetInstance(new DerSequence(tbs, algorithm, signatureBits)));
    }

    // ---- Signing (Ukrainian conventions) --------------------------------------------------------------------

    /// <summary>
    /// Signs <paramref name="data"/> with a "DSTU 4145 with …" algorithm and returns D = S‖R little-endian, as stored in
    /// certificates, CMS and XML. GOST 34.311 goes through <see cref="Dstu4145Signer.SignMessage"/> with the key's DKE;
    /// DSTU 7564 is hashed here and signed with <see cref="SignHash"/>.
    /// </summary>
    public static byte[] Sign(TestKey key, byte[] data, string signatureAlgorithm)
    {
        if (signatureAlgorithm == Oids.Dstu4145WithGost34311)
        {
            using Gost34311 hash = Gost34311.FromDke(key.Dke);
            return UaPki.Reverse(new Dstu4145Signer(key.Domain).SignMessage(key.PrivateKey, data, 0, hash));
        }
        return SignHash(key, UaPki.Hash(UaPki.HashOf(signatureAlgorithm), data));
    }

    /// <summary>
    /// Signs a hash that is already computed (CMS: the DER of the signed attributes; XML: the canonical SignedInfo).
    /// The raw digest is reversed before 5.9 and the resulting D is returned little-endian, mirroring
    /// <see cref="UaPki.VerifyDstu4145"/>.
    /// </summary>
    public static byte[] SignHash(TestKey key, byte[] rawHash) =>
        UaPki.Reverse(new Dstu4145Signer(key.Domain).SignHash(key.PrivateKey, UaPki.Reverse(rawHash)));

    public static byte[] ToFixedLittleEndian(BigInteger value, int length)
    {
        byte[] le = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[length];
        Array.Copy(le, 0, result, 0, System.Math.Min(le.Length, length));
        return result;
    }
}
