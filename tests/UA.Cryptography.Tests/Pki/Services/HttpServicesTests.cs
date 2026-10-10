using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.X509;
using Oids = UA.Cryptography.Tests.Support.Oids;

namespace UA.Cryptography.Tests.Pki.Services;

/// <summary>
/// The HTTP clients against <see cref="LocalPkiServer"/>, which parses the requests with BouncyCastle: RFC 3161 with
/// nonce and certReq, OCSP with CertID and nonce, and the error paths.
/// </summary>
public class HttpServicesTests
{
    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void TimeStampServiceAnswersTheRequest(string hashOid)
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        byte[] hash = UaPki.Hash(hashOid, "covered"u8.ToArray());

        TimeStampToken token = new HttpTimeStampService(server.TsaUrl).GetToken(hash, hashOid);
        Assert.Equal(hash, token.Imprint);
        Assert.Equal(hashOid, token.ImprintAlgorithm);
        Assert.NotNull(token.Nonce);
        Assert.Equal(pki.Tsa.Identity.Certificate.GetEncoded(), Assert.Single(token.Cms.Certificates).Encoded); // certReq honoured
        Assert.Equal(1, server.TimeStampRequests);
    }

    [Fact]
    public void ForgedTimeStampResponsesAreRejected()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] hash = new byte[32];
        var nonce = TimeStampProtocol.NewNonce();
        byte[] token = pki.Tsa.StampHash(hash, Oids.Dstu7564_256, nonce: new Org.BouncyCastle.Math.BigInteger(nonce.ToString()));
        byte[] Response(byte[] t) => new Org.BouncyCastle.Asn1.Tsp.TimeStampResp(new Org.BouncyCastle.Asn1.Cmp.PkiStatusInfo(0),
            Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(t))).GetDerEncoded();

        Assert.NotNull(TimeStampProtocol.ParseResponse(Response(token), hash, Oids.Dstu7564_256, nonce));
        Assert.Throws<InvalidDataException>(() => TimeStampProtocol.ParseResponse(Response(token), new byte[32].Select(_ => (byte)1).ToArray(), Oids.Dstu7564_256, nonce));
        Assert.Throws<InvalidDataException>(() => TimeStampProtocol.ParseResponse(Response(token), hash, Oids.Dstu7564_256, nonce + 1));
        byte[] refused = new Org.BouncyCastle.Asn1.Tsp.TimeStampResp(new Org.BouncyCastle.Asn1.Cmp.PkiStatusInfo(2), null).GetDerEncoded();
        Assert.Throws<InvalidDataException>(() => TimeStampProtocol.ParseResponse(refused, hash, Oids.Dstu7564_256, nonce));
    }

    [Fact]
    public void OcspServiceAnswersAboutTheCertificate()
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();

        OcspResponse response = new HttpOcspService(server.OcspUrl).GetResponse(signer, ca, Oids.Dstu7564_256)!;
        OcspSingleResponse single = response.Find(signer, ca)!;
        Assert.Equal(OcspCertificateStatus.Good, single.Status);
        Assert.True(response.IsSignedBy(response.FindResponder([])!));
        Assert.Equal(1, server.OcspRequests);

        // No responder named in the certificate and none given: nothing to ask.
        Assert.Null(new HttpOcspService().GetResponse(signer, ca, Oids.Dstu7564_256));
    }

    [Fact]
    public void HttpErrorsSurfaceAsExceptions()
    {
        using var server = new LocalPkiServer(Hierarchy.Shared);
        string missing = server.TsaUrl.Replace("/tsp", "/missing", StringComparison.Ordinal);
        Assert.Throws<HttpRequestException>(() => new HttpTimeStampService(missing).GetToken(new byte[32], Oids.Dstu7564_256));
    }
}
