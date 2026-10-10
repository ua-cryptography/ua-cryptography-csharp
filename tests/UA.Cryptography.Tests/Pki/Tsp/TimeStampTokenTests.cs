using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using CadesOptions = UA.Cryptography.Pki.Cades.CadesOptions;
using Oids = UA.Cryptography.Tests.Support.Oids;
using PkiCmsBuilder = UA.Cryptography.Pki.Cms.CmsBuilder;

namespace UA.Cryptography.Tests.Pki.Tsp;

/// <summary>
/// RFC 3161 tokens of the synthetic TSA (built with BouncyCastle) read by the package: the imprint, the service
/// certificate found with or without embedding, and a token over other data rejected inside a CAdES signature.
/// </summary>
public class TimeStampTokenTests
{
    private static readonly byte[] Covered = "covered bytes"u8.ToArray();

    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void TokenCoversItsDataOnly(string hashOid)
    {
        Hierarchy pki = Hierarchy.Shared;
        TimeStampToken token = TimeStampToken.Load(pki.Tsa.Stamp(Covered, hashOid));
        Assert.Equal(hashOid, token.ImprintAlgorithm);
        Assert.Equal(hashOid == Oids.Gost34311 ? Oids.TspPolicyGost34311 : Oids.TspPolicyDstu7564, token.Policy);
        Assert.True(token.Covers(Covered));
        Assert.False(token.Covers([.. Covered, 0]));

        var report = new VerificationReport("token");
        Certificate? tsa = token.Verify(Covered, [], report, "ts");
        Assert.Equal(pki.Tsa.Identity.Certificate.GetEncoded(), tsa!.Encoded);
        Assert.True(report.IsValid, string.Join("\n", report.Checks));

        report = new VerificationReport("token");
        token.Verify("other bytes"u8, [], report, "ts");
        Assert.Contains(report.Checks, c => c.Name == "ts: imprint" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void ServiceCertificateIsFoundAmongKnownOnesWhenNotEmbedded()
    {
        Hierarchy pki = Hierarchy.Shared;
        TimeStampToken token = TimeStampToken.Load(pki.Tsa.Stamp(Covered, Oids.Gost34311, includeCertificate: false));
        Assert.Null(token.FindSignerCertificate());
        Assert.Equal(pki.Tsa.Identity.Certificate.GetEncoded(), token.FindSignerCertificate(PkiLayer.AllCertificates(pki))!.Encoded);

        var report = new VerificationReport("token");
        Assert.Null(token.Verify(Covered, [], report, "ts"));
        Assert.Contains(report.Checks, c => c.Name == "ts: service certificate" && c.Status == CheckStatus.Warning);
    }

    [Fact]
    public void SignatureTimeStampOverOtherBytesFailsTheSignature()
    {
        Hierarchy pki = Hierarchy.Shared;
        SigningKey signer = PkiLayer.Signer(pki);
        byte[] data = "data"u8.ToArray();
        byte[] attributes = PkiCmsBuilder.SignedAttributes(data, UA.Cryptography.Pki.Oids.Data, signer, Oids.Dstu7564_256);
        byte[] signature = PkiCmsBuilder.SignerInfo(attributes, signer, Oids.Dstu7564_256).Signature;

        // A genuine token of the TSA, but over the data instead of the signature value.
        byte[] wrongToken = pki.Tsa.Stamp(data, Oids.Dstu7564_256);
        byte[] withWrongToken = PkiCmsBuilder.SignerInfoWith(attributes, signature, signer.Certificate, Oids.Dstu7564_256,
            [PkiCmsBuilder.Attribute(UA.Cryptography.Pki.Oids.SignatureTimeStampToken, wrongToken)]);
        byte[] cms = PkiCmsBuilder.SignedData(withWrongToken, Oids.Dstu7564_256, UA.Cryptography.Pki.Oids.Data, data, [signer.Certificate]);

        VerificationResult result = CadesVerifier.Verify(cms, null, new ValidationOptions { ExtraCertificates = PkiLayer.AllCertificates(pki) });
        Assert.False(result.IsValid);
        VerificationReport report = result.Signatures[0];
        Assert.Contains(report.Checks, c => c.Name == "signature time-stamp: imprint" && c.Status == CheckStatus.Failed);
        Assert.Null(report.TimeStampTime);

        // The same signer with a correct token is valid.
        byte[] good = new CadesSigner(signer, PkiLayer.Services(pki)).Sign(data, new CadesOptions(Level: SignatureLevel.T));
        Assert.True(CadesVerifier.Verify(good, null, new ValidationOptions { ExtraCertificates = PkiLayer.AllCertificates(pki) }).IsValid);
    }
}
