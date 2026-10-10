using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using BcTimeStampToken = Org.BouncyCastle.Tsp.TimeStampToken;
using CadesOptions = UA.Cryptography.Pki.Cades.CadesOptions;
using Oids = UA.Cryptography.Tests.Support.Oids;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using PkiCmsBuilder = UA.Cryptography.Pki.Cms.CmsBuilder;
using SignatureLevel = UA.Cryptography.Pki.SignatureLevel;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Pki.Cades;

/// <summary>
/// CAdES made by the package and checked by the independent BouncyCastle-based recipes of <see cref="UaPki"/>, and CAdES
/// made by the test builder (<see cref="CadesBuilder"/>) checked by the package's verifier; negative cases for every check.
/// </summary>
public class CadesSignerTests
{
    private static readonly byte[] Data = "Документ для підпису"u8.ToArray();

    public static TheoryData<string, bool> Variants => new()
    {
        { Oids.Dstu7564_256, false },
        { Oids.Dstu7564_256, true },
        { Oids.Gost34311, false },
        { Oids.Gost34311, true },
    };

    private static ValidationOptions Trusting(Hierarchy pki) => new() { TrustAnchors = [PkiLayer.Root(pki)], ExtraCertificates = PkiLayer.AllCertificates(pki) };

    private static byte[] Sign(CadesOptions options) =>
        new CadesSigner(PkiLayer.Signer(Hierarchy.Shared), PkiLayer.Services(Hierarchy.Shared)).Sign(Data, options);

    [Theory]
    [MemberData(nameof(Variants))]
    public void PackageSignatureVerifiesByTheBouncyCastleRecipe(string hashOid, bool detached)
    {
        var cms = new CmsSignedData(Sign(new CadesOptions(hashOid, detached)));
        SignerInformation signer = Assert.Single(cms.GetSignerInfos().GetSigners());
        Assert.Equal(hashOid, signer.DigestAlgorithmID.Algorithm.Id);
        Assert.Equal(UaPki.SignatureAlgorithmFor(hashOid), signer.SignatureAlgorithm.Algorithm.Id);
        Assert.Equal(detached, cms.SignedContent is null);

        // messageDigest, signingCertificateV2 and the DSTU 4145 signature, each recomputed by the test code.
        Assert.Equal(UaPki.Hash(hashOid, Data), UaPki.MessageDigest(signer));
        Assert.True(UaPki.VerifyCmsSigner(signer, Hierarchy.Shared.Signer.Certificate));
        Assert.NotNull(UaPki.SignedAttribute(signer, PkcsObjectIdentifiers.Pkcs9AtSigningTime));
        Assert.Equal(64, signer.GetSignature().Length);
    }

    [Theory]
    [MemberData(nameof(Variants))]
    public void PackageSignatureVerifiesByThePackage(string hashOid, bool detached)
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] signature = Sign(new CadesOptions(hashOid, detached));
        VerificationResult result = CadesVerifier.Verify(signature, detached ? Data : null, Trusting(pki));
        Assert.True(result.IsValid, Describe(result));
        Assert.Equal(Data, result.SignedFiles["content"]);
        VerificationReport report = Assert.Single(result.Signatures);
        Assert.Equal(pki.Signer.Certificate.GetEncoded(), report.Signer!.Encoded);
        Assert.Contains(report.Checks, c => c.Name == "signer: trust" && c.Status == CheckStatus.Passed);
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256, true, CadesLevel.B, false)]
    [InlineData(Oids.Dstu7564_256, false, CadesLevel.T, true)]
    [InlineData(Oids.Gost34311, true, CadesLevel.T, false)]
    [InlineData(Oids.Dstu7564_256, true, CadesLevel.XLong, false)]
    [InlineData(Oids.Gost34311, false, CadesLevel.XLong, true)]
    public void TestBuilderSignatureVerifiesByThePackage(string hashOid, bool enveloped, CadesLevel level, bool contentTimeStamp)
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] signature = CadesBuilder.Build(Data, pki, new Support.CadesOptions(hashOid, enveloped, level, contentTimeStamp));
        VerificationResult result = CadesVerifier.Verify(signature, enveloped ? null : Data, Trusting(pki));
        Assert.True(result.IsValid, Describe(result));

        VerificationReport report = result.Signatures[0];
        if (level >= CadesLevel.T)
        {
            Assert.NotNull(report.TimeStampTime);
            Assert.Contains(report.Checks, c => c.Name == "signature time-stamp: imprint" && c.Status == CheckStatus.Passed);
        }
        if (contentTimeStamp)
            Assert.Contains(report.Checks, c => c.Name == "content time-stamp: imprint" && c.Status == CheckStatus.Passed);
        if (level == CadesLevel.XLong)
        {
            Assert.Contains(report.Checks, c => c.Name == "certificate references" && c.Status == CheckStatus.Passed);
            Assert.Contains(report.Checks, c => c.Name == "revocation references" && c.Status == CheckStatus.Passed);
            Assert.Equal(2, report.Checks.Count(c => c.Name.StartsWith("signer: revocation", StringComparison.Ordinal) && c.Status == CheckStatus.Passed));
        }
        else
        {
            Assert.Contains(report.Checks, c => c.Name.StartsWith("signer: revocation", StringComparison.Ordinal) && c.Status == CheckStatus.Warning);
        }
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void PackageLevelsTAndLtAreReadByBouncyCastle(string hashOid)
    {
        Hierarchy pki = Hierarchy.Shared;
        var cms = new CmsSignedData(Sign(new CadesOptions(hashOid, Level: SignatureLevel.LT, ContentTimeStamp: true)));
        SignerInformation signer = Assert.Single(cms.GetSignerInfos().GetSigners());

        // Both time-stamps are RFC 3161 tokens for BouncyCastle, signed by the TSA and covering the right bytes.
        var signatureToken = new CmsSignedData(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAASignatureTimeStampToken).ToAsn1Object().GetEncoded());
        Assert.True(UaPki.ImprintCovers(UaPki.ReadTimeStamp(signatureToken), signer.GetSignature()));
        Assert.Equal(pki.Tsa.Identity.Certificate.SerialNumber, new BcTimeStampToken(signatureToken).SignerID.SerialNumber);
        var contentToken = new CmsSignedData(UaPki.SignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsContentTimestamp).ToAsn1Object().GetEncoded());
        Assert.True(UaPki.ImprintCovers(UaPki.ReadTimeStamp(contentToken), Data));
        Assert.True(UaPki.VerifyCmsSigner(Assert.Single(signatureToken.GetSignerInfos().GetSigners()), pki.Tsa.Identity.Certificate));

        // CAdES-X Long: BouncyCastle parses the references and the values, and they agree.
        var certificates = Asn1Sequence.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsCertValues)).Cast<Asn1Encodable>()
            .Select(c => c.GetDerEncoded()).ToList();
        Assert.Contains(pki.IssuingCa.Certificate.GetEncoded(), certificates);
        Assert.Contains(pki.Root.Certificate.GetEncoded(), certificates);
        foreach (OtherCertID reference in CompleteCertificateRefs.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsCertificateRefs)).GetOtherCertIDs())
            Assert.Contains(certificates, c => UaPki.Hash(reference.OtherCertHash.HashAlgorithm.Algorithm.Id, c).SequenceEqual(reference.OtherCertHash.GetHashValue()));

        var responses = RevocationValues.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsRevocationValues)).GetOcspVals();
        Assert.Equal(2, responses.Length);
        X509Certificate[] known = [pki.Signer.Certificate, .. pki.ValidationCertificates];
        Assert.All(responses, r => Assert.True(UaPki.VerifyOcsp(r, UaPki.FindOcspResponder(r, known))));
        var ocspRefs = CompleteRevocationRefs.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsRevocationRefs))
            .GetCrlOcspRefs().SelectMany(r => r.OcspIDs.GetOcspResponses()).ToList();
        Assert.All(ocspRefs, reference => Assert.Contains(responses,
            r => UaPki.Hash(reference.OcspRepHash.HashAlgorithm.Algorithm.Id, r.GetDerEncoded()).SequenceEqual(reference.OcspRepHash.GetHashValue())));

        // And the package's own verifier finds nothing missing.
        VerificationResult result = CadesVerifier.Verify(cms.GetEncoded(), null, Trusting(pki));
        Assert.True(result.IsValid, Describe(result));
        Assert.DoesNotContain(result.Signatures[0].Checks, c => c.Name.StartsWith("signer:", StringComparison.Ordinal) && c.Status != CheckStatus.Passed);
    }

    [Fact]
    public void TamperedDataFailsTheMessageDigest()
    {
        byte[] signature = Sign(new CadesOptions(Detached: true));
        byte[] tampered = Data.ToArray();
        tampered[^1] ^= 1;
        VerificationResult result = CadesVerifier.Verify(signature, tampered, Trusting(Hierarchy.Shared));
        Assert.False(result.IsValid);
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "CMS: messageDigest" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void TamperedSignatureValueFails()
    {
        byte[] signature = Sign(new CadesOptions());
        byte[] d = CmsSignerSignature(signature);
        int offset = signature.AsSpan().IndexOf(d);
        signature[offset + 10] ^= 1;
        VerificationResult result = CadesVerifier.Verify(signature, null, Trusting(Hierarchy.Shared));
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "CMS: signature" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void ForeignCertificateFailsTheSigningCertificateCheck()
    {
        // A second certificate for the same key, issuer and serial number: the signer identifier cannot tell them apart,
        // the signingCertificateV2 hash can.
        Hierarchy pki = Hierarchy.Shared;
        SigningKey signer = PkiLayer.Signer(pki);
        Certificate twin = new CertificateBuilder(signer.Certificate.Subject, signer.Key.PublicKey) { SerialNumber = signer.Certificate.SerialNumber }
            .Issue(pki.IssuingCa.Certificate.ToPki(), pki.IssuingCa.Key.ToPki());
        var twinSigner = new SigningKey(signer.Key, [twin, .. signer.Chain.Skip(1)]);

        byte[] attributes = PkiCmsBuilder.SignedAttributes(Data, UA.Cryptography.Pki.Oids.Data, twinSigner, Oids.Dstu7564_256);
        byte[] signerInfo = PkiCmsBuilder.SignerInfo(attributes, twinSigner, Oids.Dstu7564_256).SignerInfo;
        byte[] honest = PkiCmsBuilder.SignedData(signerInfo, Oids.Dstu7564_256, UA.Cryptography.Pki.Oids.Data, Data, [twin]);
        byte[] swapped = PkiCmsBuilder.SignedData(signerInfo, Oids.Dstu7564_256, UA.Cryptography.Pki.Oids.Data, Data, [signer.Certificate]);

        Assert.True(CadesVerifier.Verify(honest, null, Trusting(pki)).IsValid);
        VerificationResult forged = CadesVerifier.Verify(swapped, null, Trusting(pki));
        Assert.False(forged.IsValid);
        Assert.Contains(forged.Signatures[0].Checks, c => c.Name == "CMS: signing certificate" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void SigningCertificateV2NamesTheIssuerAndSerialNumber()
    {
        // As IIT and the banks write it: ESSCertIDv2 { hashAlgorithm, certHash, issuerSerial }.
        Hierarchy pki = Hierarchy.Shared;
        byte[] signature = Sign(new CadesOptions());
        var attribute = new CmsSignedData(signature).GetSignerInfos().GetSigners().Cast<SignerInformation>().Single()
            .SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificateV2];
        EssCertIDv2 id = SigningCertificateV2.GetInstance(attribute.AttrValues[0]).GetCerts().Single();
        Assert.Equal(pki.Signer.Certificate.SerialNumber, id.IssuerSerial.Serial.Value);
        Assert.Equal(pki.IssuingCa.Certificate.SubjectDN.GetEncoded(), id.IssuerSerial.Issuer.GetNames().Single().Name.ToAsn1Object().GetEncoded());

        VerificationResult result = CadesVerifier.Verify(signature, null, Trusting(pki));
        Assert.True(result.IsValid, Describe(result));
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "CMS: signing certificate"
            && c.Details.EndsWith("and so do its issuer and serial number", StringComparison.Ordinal));

        // The right hash with another serial number in issuerSerial does not pass.
        SigningKey signer = PkiLayer.Signer(pki);
        Certificate certificate = signer.Certificate;
        byte[] wrongSerial = Der.Sequence(Der.Sequence(Der.Explicit(4, certificate.Issuer.Encoded)), Der.Integer(certificate.SerialNumber + 1));
        byte[] attributes = Der.SetOf(
            PkiCmsBuilder.Attribute(UA.Cryptography.Pki.Oids.ContentType, Der.ObjectIdentifier(UA.Cryptography.Pki.Oids.Data)),
            PkiCmsBuilder.Attribute(UA.Cryptography.Pki.Oids.MessageDigest, Der.OctetString(PkiAlgorithms.Hash(Oids.Dstu7564_256, Data, signer.Key.Dke))),
            PkiCmsBuilder.Attribute(UA.Cryptography.Pki.Oids.SigningCertificateV2, Der.Sequence(Der.Sequence(Der.Sequence(
                Der.AlgorithmIdentifier(Oids.Dstu7564_256), Der.OctetString(PkiAlgorithms.Hash(Oids.Dstu7564_256, certificate.Encoded)), wrongSerial)))));
        byte[] signerInfo = PkiCmsBuilder.SignerInfo(attributes, signer, Oids.Dstu7564_256).SignerInfo;
        byte[] forged = PkiCmsBuilder.SignedData(signerInfo, Oids.Dstu7564_256, UA.Cryptography.Pki.Oids.Data, Data, [certificate]);
        result = CadesVerifier.Verify(forged, null, Trusting(pki));
        Assert.False(result.IsValid);
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "CMS: signing certificate" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void TimeStampWithoutTheServiceCertificateIsCompletedFromCaIssuers()
    {
        // The shape PrivatBank hands out: CAdES-T with only the signer's certificate, the token without the TSA's, and the
        // provider's whole set (CA and TSA certificates) published at the signer certificate's caIssuers address.
        Hierarchy pki = Hierarchy.Shared;
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Certificate root = PkiLayer.Root(pki);
        Certificate tsa = pki.Tsa.Identity.Certificate.ToPki();
        Dstu4145PrivateKey key = pki.Signer.Key.ToPki();
        Certificate certificate = new CertificateBuilder(pki.Signer.Certificate.ToPki().Subject, key.PublicKey)
            .AddKeyUsage(KeyUsageFlags.DigitalSignature | KeyUsageFlags.NonRepudiation)
            .AddAuthorityInfoAccess(null, "http://ca.test/bundle.p7b")
            .Issue(ca, pki.IssuingCa.Key.ToPki());
        var services = new SignatureServices { TimeStamps = new PkiLayer.TimeStamps(pki, includeCertificate: false) };
        byte[] signature = new CadesSigner(new SigningKey(key, [certificate]), services).Sign(Data, new CadesOptions(Level: SignatureLevel.T));

        // Offline the token cannot be checked: a warning, and its time is not used.
        VerificationReport offline = CadesVerifier.Verify(signature, null, new ValidationOptions()).Signatures[0];
        Assert.True(offline.IsValid, string.Join("\n", offline.Checks));
        Assert.Contains(offline.Checks, c => c.Name == "signature time-stamp: service certificate" && c.Status == CheckStatus.Warning);
        Assert.Null(offline.TimeStampTime);

        // With downloads the bundle completes both the time-stamp and the signer's path, in one download.
        var downloads = new Downloads(ca, tsa);
        VerificationReport online = CadesVerifier.Verify(signature, null, new ValidationOptions { TrustAnchors = [root], Downloads = downloads }).Signatures[0];
        Assert.True(online.IsValid, string.Join("\n", online.Checks));
        Assert.Contains(online.Checks, c => c.Name == "signature time-stamp: signature" && c.Status == CheckStatus.Passed);
        Assert.Contains(online.Checks, c => c.Name == "signer: trust" && c.Status == CheckStatus.Passed);
        Assert.Equal(online.TimeStamps.Single().Token.GenTime, online.TimeStampTime);
        Assert.Equal(["http://ca.test/bundle.p7b"], downloads.Urls);
    }

    private sealed class Downloads(params Certificate[] certificates) : ICertificateSource
    {
        public List<string> Urls { get; } = [];

        public IReadOnlyList<Certificate> Download(string url)
        {
            Urls.Add(url);
            return certificates;
        }
    }

    [Fact]
    public void DetachedSignatureWithoutDataAndUntrustedRootFail()
    {
        byte[] signature = Sign(new CadesOptions(Detached: true));
        Assert.Contains(CadesVerifier.Verify(signature, null, new ValidationOptions()).Signatures[0].Checks,
            c => c.Name == "content" && c.Status == CheckStatus.Failed);

        Certificate[] czo = Directory.GetFiles(TestFiles.CzoRoots, "*.cer").Select(Certificate.Load).ToArray();
        VerificationResult untrusted = CadesVerifier.Verify(signature, Data, new ValidationOptions { TrustAnchors = czo });
        Assert.False(untrusted.IsValid);
        Assert.Contains(untrusted.Signatures[0].Checks, c => c.Name == "signer: trust" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void LevelTWithoutTimeStampServiceIsRefused()
    {
        var signer = new CadesSigner(PkiLayer.Signer(Hierarchy.Shared));
        Assert.Throws<InvalidOperationException>(() => signer.Sign(Data, new CadesOptions(Level: SignatureLevel.T)));
    }

    private static byte[] CmsSignerSignature(byte[] signature) =>
        Assert.Single(new CmsSignedData(signature).GetSignerInfos().GetSigners()).GetSignature();

    internal static string Describe(VerificationResult result) => string.Join("\n", result.Signatures.SelectMany(
        r => r.Checks.Where(c => c.Status != CheckStatus.Passed).Select(c => $"{r.Title}: [{c.Status}] {c.Name}: {c.Details}")));
}
