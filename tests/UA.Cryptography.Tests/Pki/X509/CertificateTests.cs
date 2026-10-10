using Org.BouncyCastle.Asn1.X509;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Math;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.X509;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using Oids = UA.Cryptography.Tests.Support.Oids;
using PkiOids = UA.Cryptography.Pki.Oids;

namespace UA.Cryptography.Tests.Pki.X509;

/// <summary>
/// The package's X.509 layer on the public certificates of Ukrainian CAs and on the synthetic hierarchy: parsed fields
/// equal BouncyCastle's, keys equal those of <see cref="UaPki.ReadPublicKey"/>, signatures verify, and certificates the
/// package issues are accepted by BouncyCastle and by the independent recipes of <see cref="UaPki"/>.
/// </summary>
public class CertificateTests
{
    public static TheoryData<string> RealCertificates => new(
        new[] { TestFiles.CzoRoots, TestFiles.Intermediates, TestFiles.HistoricalCertificates }
            .SelectMany(d => Directory.GetFiles(d).Where(f => f.EndsWith(".cer", StringComparison.Ordinal) || f.EndsWith(".crt", StringComparison.Ordinal)))
            .Select(f => Path.GetRelativePath(TestFiles.Root, f).Replace('\\', '/'))
            .Order());

    private static (Certificate Ours, BcCertificate Bc) Load(string relative)
    {
        byte[] der = TestFiles.Read(relative.Split('/'));
        return (Certificate.Load(der), UaPki.ParseCertificate(der));
    }

    [Theory]
    [MemberData(nameof(RealCertificates))]
    public void RealCertificateParsesLikeBouncyCastle(string file)
    {
        var (ours, bc) = Load(file);
        Assert.Equal(bc.Version, ours.Version);
        Assert.Equal(bc.SerialNumber.ToString(), ours.SerialNumber.ToString());
        Assert.Equal(bc.SubjectDN.GetDerEncoded(), ours.Subject.Encoded);
        Assert.Equal(bc.IssuerDN.GetDerEncoded(), ours.Issuer.Encoded);
        Assert.Equal(new DateTimeOffset(bc.NotBefore.ToUniversalTime(), TimeSpan.Zero), ours.NotBefore);
        Assert.Equal(new DateTimeOffset(bc.NotAfter.ToUniversalTime(), TimeSpan.Zero), ours.NotAfter);
        Assert.Equal(bc.SigAlgOid, ours.SignatureAlgorithm);
        Assert.Equal(bc.GetTbsCertificate(), ours.TbsEncoded);
        Assert.Equal(bc.GetSignature(), ours.SignatureValue);
        Assert.Equal(bc.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded(), ours.SubjectPublicKeyInfo);
        Assert.Equal(bc.GetNonCriticalExtensionOids().Count + bc.GetCriticalExtensionOids().Count, ours.Extensions.Count);
        Assert.Equal(bc.GetBasicConstraints() >= 0, ours.IsCa);

        var (parameters, publicKey, dke) = UaPki.ReadPublicKey(bc);
        Assert.Equal(parameters.Field.M, ours.PublicKey.Domain.Field.M);
        Assert.Equal(parameters.N, ours.PublicKey.Domain.N);
        Assert.Equal(publicKey.AffineX.ToBigInteger(), ours.PublicKey.Q.AffineX.ToBigInteger());
        Assert.Equal(publicKey.AffineY.ToBigInteger(), ours.PublicKey.Q.AffineY.ToBigInteger());
        Assert.Equal(dke, ours.PublicKey.Dke);
    }

    [Theory]
    [InlineData("czo-roots/czo-root-2027-gost34311.cer", "czo-roots/czo-root-2027-gost34311.cer")]
    [InlineData("czo-roots/czo-root-2036-dstu7564.cer", "czo-roots/czo-root-2036-dstu7564.cer")]
    [InlineData("historical/bitis-corp-2009.crt", "historical/bitis-root-2009.crt")]
    [InlineData("historical/ucc-ca-2010.crt", "historical/czo-root-2005.crt")]
    [InlineData("historical/ucc-tsp-2010.crt", "historical/ucc-ca-2010.crt")]
    public void RealCertificateSignatureVerifies(string subject, string issuer)
    {
        Certificate certificate = Load("certificates/" + subject).Ours;
        Certificate issuerCertificate = Load("certificates/" + issuer).Ours;
        Assert.True(certificate.IsSignedBy(issuerCertificate));

        // One changed byte of the signed part breaks the signature.
        byte[] tampered = certificate.Encoded.ToArray();
        int offset = certificate.Encoded.AsSpan().IndexOf(certificate.Subject.Encoded) + certificate.Subject.Encoded.Length - 1;
        tampered[offset] ^= 1;
        Assert.False(Certificate.Load(tampered).IsSignedBy(issuerCertificate));
    }

    [Fact]
    public void DiiaCaIsIssuedByACzoRoot()
    {
        Certificate dia = Certificate.Load(TestFiles.Read("certificates", "intermediates", "dia-knedp.cer"));
        Certificate[] roots = Directory.GetFiles(TestFiles.CzoRoots, "*.cer").Select(Certificate.Load).ToArray();
        Assert.Single(roots, dia.IsSignedBy);
        Assert.NotEmpty(dia.OcspUrls.Concat(dia.CaIssuerUrls).Concat(dia.TimeStampUrls));
    }

    [Fact]
    public void SyntheticHierarchyVerifiesWithThePackage()
    {
        Hierarchy pki = Hierarchy.Shared;
        Certificate root = pki.Root.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Assert.True(root.IsSignedBy(root));
        Assert.True(ca.IsSignedBy(root));
        Assert.True(pki.Signer.Certificate.ToPki().IsSignedBy(ca));
        Assert.False(pki.Signer.Certificate.ToPki().IsSignedBy(root));
        Assert.Contains(PkiOids.KeyPurposeTimeStamping, pki.Tsa.Identity.Certificate.ToPki().ExtendedKeyUsage);
    }

    [Theory]
    [InlineData(Oids.Dstu4145WithDstu7564, 257)]
    [InlineData(Oids.Dstu4145WithGost34311, 431)]
    [InlineData(Oids.Dstu4145WithDstu7564, 163)]
    public void IssuedCertificatesAreAcceptedByBouncyCastleAndUaPki(string signatureAlgorithm, int m)
    {
        Dstu4145PrivateKey rootKey = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(m));
        Certificate root = new CertificateBuilder(DistinguishedName.Parse("CN=Package Root,O=UA Cryptography Tests,C=UA"), rootKey.PublicKey)
        {
            SignatureAlgorithm = signatureAlgorithm,
        }.AddBasicConstraints(true).AddKeyUsage(KeyUsageFlags.KeyCertSign | KeyUsageFlags.CrlSign).AddSubjectKeyIdentifier().SelfSign(rootKey);

        Dstu4145PrivateKey leafKey = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(257));
        Certificate leaf = new CertificateBuilder(DistinguishedName.Parse("CN=Package Leaf,O=UA Cryptography Tests,C=UA"), leafKey.PublicKey)
        {
            SignatureAlgorithm = signatureAlgorithm,
        }
            .AddBasicConstraints(false)
            .AddKeyUsage(KeyUsageFlags.DigitalSignature | KeyUsageFlags.NonRepudiation)
            .AddAuthorityKeyIdentifier(root.SubjectKeyIdentifier!)
            .AddAuthorityInfoAccess("http://ocsp.example/", "http://ca.example/ca.cer")
            .AddTimeStampingUrl("http://tsp.example/")
            .Issue(root, rootKey);

        // BouncyCastle parses them, and the BouncyCastle-based recipe verifies the signatures.
        BcCertificate bcRoot = UaPki.ParseCertificate(root.Encoded);
        BcCertificate bcLeaf = UaPki.ParseCertificate(leaf.Encoded);
        Assert.True(UaPki.VerifyCertificate(bcRoot, bcRoot));
        Assert.True(UaPki.VerifyCertificate(bcLeaf, bcRoot));
        Assert.Equal(signatureAlgorithm, bcLeaf.SigAlgOid);
        Assert.True(bcRoot.GetBasicConstraints() >= 0);
        Assert.Equal(-1, bcLeaf.GetBasicConstraints());
        Assert.Equal([true, true, false, false, false, false, false, false, false], bcLeaf.GetKeyUsage());
        Assert.Equal(leafKey.PublicKey.Q, UaPki.ReadPublicKey(bcLeaf).PublicKey);

        // The package reads its own extensions back.
        Assert.Equal(["http://ocsp.example/"], leaf.OcspUrls);
        Assert.Equal(["http://ca.example/ca.cer"], leaf.CaIssuerUrls);
        Assert.Equal(["http://tsp.example/"], leaf.TimeStampUrls);
        Assert.Equal(root.SubjectKeyIdentifier, leaf.AuthorityKeyIdentifier);
        Assert.Equal(0b11, leaf.KeyUsage);
        Assert.True(leaf.IsSignedBy(root));
        Assert.False(root.IsSignedBy(leaf));
    }

    [Fact]
    public void NormalBasisKeyRoundTripsThroughExplicitParameters()
    {
        // The national PKI does not use ONB and BouncyCastle has none: the explicit ECBinary form without a polynomial.
        Dstu4145PrivateKey key = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.OptimalNormal(173));
        byte[] spki = key.PublicKey.ToSubjectPublicKeyInfo();
        Dstu4145PublicKey parsed = Dstu4145PublicKey.FromSubjectPublicKeyInfo(Asn1Node.Parse(spki));
        Assert.IsType<OptimalNormalBasisField>(parsed.Domain.Field);
        Assert.Equal(key.PublicKey.Q.AffineX.ToBigInteger(), parsed.Q.AffineX.ToBigInteger());

        byte[] signature = key.SignHash(new byte[32]);
        Assert.True(parsed.VerifyHash(new byte[32], signature));
        Assert.Equal(key.D, Dstu4145PrivateKey.FromPkcs8(key.ToPkcs8()).D);
    }

    [Theory]
    [InlineData(131)]
    [InlineData(600)]
    [InlineData(100000)]
    public void ExplicitFieldDegreesOutsideTheStandardTablesAreRejected(int m)
    {
        // An attacker-chosen huge field would make the checks of section 8 arbitrarily expensive.
        byte[] ecBinary = Der.Sequence(Der.Sequence(Der.Integer(m), Der.Integer(3)), Der.Integer(0), Der.OctetString(new byte[8]),
            Der.Integer(12345), Der.OctetString(new byte[8]));
        byte[] spki = Der.Sequence(Der.Sequence(Der.ObjectIdentifier(PkiOids.Dstu4145Le), Der.Sequence(ecBinary)),
            Der.BitString(Der.OctetString(new byte[8])));
        Assert.Throws<InvalidDataException>(() => Dstu4145PublicKey.FromSubjectPublicKeyInfo(Asn1Node.Parse(spki)));
    }

    [Fact]
    public void BigEndianKeyOidReversesTheOctetStrings()
    {
        Dstu4145PrivateKey le = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(257));
        var be = new Dstu4145PrivateKey(le.Domain, le.D, le.Dke, littleEndian: false);
        Asn1Node leSpki = Asn1Node.Parse(le.PublicKey.ToSubjectPublicKeyInfo());
        Asn1Node beSpki = Asn1Node.Parse(be.PublicKey.ToSubjectPublicKeyInfo());
        Assert.Equal(PkiOids.Dstu4145Be, beSpki[0][0].GetOid());
        byte[] q = Asn1Node.Parse(leSpki[1].GetBitString()).GetOctetString();
        Array.Reverse(q);
        Assert.Equal(q, Asn1Node.Parse(beSpki[1].GetBitString()).GetOctetString());
        Assert.Equal(le.PublicKey.Q, Dstu4145PublicKey.FromSubjectPublicKeyInfo(beSpki).Q);
        Assert.Equal(le.D, Dstu4145PrivateKey.FromPkcs8(be.ToPkcs8()).D);
    }

    [Fact]
    public void DistinguishedNameEncodesLikeBouncyCastle()
    {
        const string dn = "CN=Test Signer,O=UA Cryptography Tests,OU=Unit,L=Kyiv,C=UA,SERIALNUMBER=UA-12345";
        Assert.Equal(new X509Name(dn).GetDerEncoded(), DistinguishedName.Parse(dn).Encoded);

        DistinguishedName cyrillic = DistinguishedName.Parse("CN=Тестовий підписувач, O=Організація\\, ТОВ, C=UA");
        Assert.Equal("Тестовий підписувач", cyrillic.Get(PkiOids.CommonName));
        Assert.Equal("Організація, ТОВ", cyrillic.Get(PkiOids.Organization));
        Assert.Equal(cyrillic, DistinguishedName.FromAsn1(Asn1Node.Parse(cyrillic.Encoded)));
        Assert.Equal(new X509Name(cyrillic.ToString()).GetDerEncoded(), cyrillic.Encoded);
        Assert.Throws<FormatException>(() => DistinguishedName.Parse("XX=1"));
    }

    [Fact]
    public void PemAndDerLoadTheSameCertificate()
    {
        Certificate der = Certificate.Load(TestFiles.Read("certificates", "intermediates", "dia-knedp.cer"));
        Certificate pem = Certificate.Load(System.Text.Encoding.ASCII.GetBytes(Pem.Encode(der.Encoded, "CERTIFICATE")));
        Assert.Equal(der, pem);
    }
}
