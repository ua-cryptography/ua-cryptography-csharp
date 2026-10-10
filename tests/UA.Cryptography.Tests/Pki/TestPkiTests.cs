using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Dstu4145;
using BcBasicOcspResp = Org.BouncyCastle.Ocsp.BasicOcspResp;
using BcTimeStampToken = Org.BouncyCastle.Tsp.TimeStampToken;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Pki;

/// <summary>
/// The synthetic PKI every signature test is built on (<see cref="TestPki"/>, <see cref="Hierarchy"/>): keys,
/// certificates, time-stamps, OCSP responses and JKS key stores, each verified with this library's own code and, where
/// BouncyCastle has a parser, accepted by it as structurally valid.
/// </summary>
public class TestPkiTests
{
    [Fact]
    public void SelfSignedCertificateCarriesTheKeyAndVerifies()
    {
        TestPki.TestIdentity root = TestPki.CreateSelfSigned("CN=Standalone Root,C=UA");

        var (parameters, publicKey, dke) = UaPki.ReadPublicKey(root.Certificate);
        Assert.Equal(257, parameters.Field.M);
        Assert.Equal(root.Key.PublicKey, publicKey);
        Assert.Equal(root.Key.Dke, dke);
        Assert.True(UaPki.VerifyCertificate(root.Certificate, root.Certificate));
    }

    [Theory]
    [InlineData(Oids.Dstu4145WithGost34311)]
    [InlineData(Oids.Dstu4145WithDstu7564)]
    public void IssuedCertificateVerifiesWithIssuerKeyOnly(string signatureAlgorithm)
    {
        TestPki.TestIdentity root = TestPki.CreateSelfSigned("CN=Root,C=UA", signatureAlgorithm: signatureAlgorithm);
        TestPki.TestIdentity leaf = TestPki.Issue("CN=Leaf,C=UA", TestPki.GenerateKey(), root, signatureAlgorithm: signatureAlgorithm);

        Assert.Equal(signatureAlgorithm, leaf.Certificate.SigAlgOid);
        Assert.True(UaPki.VerifyCertificate(leaf.Certificate, root.Certificate));
        Assert.False(UaPki.VerifyCertificate(leaf.Certificate, TestPki.CreateSelfSigned("CN=Root,C=UA").Certificate));
    }

    [Fact]
    public void HierarchyMirrorsTheNationalChain()
    {
        Hierarchy pki = Hierarchy.Shared;
        Assert.Equal(431, pki.Root.Key.M);
        Assert.Equal(257, pki.Signer.Key.M);
        X509Certificate[] all = [pki.Signer.Certificate, .. pki.ValidationCertificates];
        Assert.All(all, c => Assert.True(UaPki.ChainsToTrusted(c, all, [pki.Root.Certificate])));
        Assert.All(all, c => Assert.Equal(Oids.Dstu4145WithDstu7564, c.SigAlgOid));
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void TimeStampTokenCoversDataAndIsSignedByTheTsa(string hashOid)
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] data = RandomNumberGenerator.GetBytes(100);
        var token = new CmsSignedData(pki.Tsa.Stamp(data, hashOid));

        TstInfo info = UaPki.ReadTimeStamp(token);
        Assert.Equal(hashOid, info.MessageImprint.HashAlgorithm.Algorithm.Id);
        Assert.True(UaPki.ImprintCovers(info, data));
        Assert.False(UaPki.ImprintCovers(info, [.. data, 0]));

        X509Certificate tsa = UaPki.FindTimeStampSigner(token, [])!;
        Assert.Equal(pki.Tsa.Identity.Certificate, tsa);
        Assert.True(UaPki.VerifyCmsSigner(Assert.Single(token.GetSignerInfos().GetSigners()), tsa));

        // BouncyCastle accepts the token as an RFC 3161 token (TSTInfo content, signingCertificateV2).
        Assert.Equal(info.SerialNumber.Value, new BcTimeStampToken(token).TimeStampInfo.SerialNumber);
    }

    [Fact]
    public void TimeStampSignerIsFoundByIssuerAndSerialWhenNotEmbedded()
    {
        Hierarchy pki = Hierarchy.Shared;
        var token = new CmsSignedData(pki.Tsa.Stamp([1, 2, 3], Oids.Gost34311, includeCertificate: false));
        Assert.Null(UaPki.FindTimeStampSigner(token, []));
        Assert.Equal(pki.Tsa.Identity.Certificate, UaPki.FindTimeStampSigner(token, pki.ValidationCertificates));
    }

    [Fact]
    public void OcspResponseIsSignedByTheResponderAndGood()
    {
        Hierarchy pki = Hierarchy.Shared;
        BasicOcspResponse response = pki.IssuingCaOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate);

        X509Certificate responder = UaPki.FindOcspResponder(response, []);
        Assert.Equal(pki.IssuingCaOcsp.Identity.Certificate, responder);
        Assert.True(UaPki.VerifyOcsp(response, responder));
        Assert.False(UaPki.VerifyOcsp(response, pki.RootOcsp.Identity.Certificate));

        SingleResponse single = SingleResponse.GetInstance(Assert.Single(response.TbsResponseData.Responses));
        Assert.Equal(0, single.CertStatus.TagNo); // good
        Assert.Equal(pki.Signer.Certificate.SerialNumber, single.CertId.SerialNumber.Value);

        // The full OCSPResponse round-trips, and BouncyCastle parses the basic response.
        BasicOcspResponse decoded = UaPki.ReadOcspResponse(OcspResponder.Encode(response));
        Assert.Equal(response.GetDerEncoded(), decoded.GetDerEncoded());
        Assert.Single(new BcBasicOcspResp(decoded).Responses);
    }

    [Fact]
    public void JksRoundTripRecoversKeyAndChain()
    {
        Hierarchy pki = Hierarchy.Shared;
        const string password = "correct horse battery staple";
        byte[] store = Jks.Write("signer", pki.Signer.Key, pki.SignerChain, password);

        Jks.Entry entry = Jks.Read(store, password);
        Assert.Equal("signer", entry.Alias);
        Assert.Equal(pki.Signer.Key.PrivateKey, entry.Key.PrivateKey);
        Assert.Equal(pki.Signer.Key.PublicKey, entry.Key.PublicKey);
        Assert.Equal(pki.Signer.Key.PublicKey, new Dstu4145Signer(entry.Key.Domain).ComputePublicKey(entry.Key.PrivateKey));
        Assert.Equal(pki.SignerChain.Select(c => c.GetEncoded()), entry.Chain.Select(c => c.GetEncoded()));
        Assert.True(UaPki.VerifyCertificate(entry.Chain[0], entry.Chain[1]));
    }

    [Fact]
    public void JksWithWrongPasswordIsRejected()
    {
        TestPki.TestIdentity id = TestPki.CreateSelfSigned("CN=Signer,C=UA");
        byte[] store = Jks.Write("signer", id.Key, [id.Certificate], "right");
        Assert.ThrowsAny<CryptographicException>(() => Jks.Read(store, "wrong"));
    }
}
