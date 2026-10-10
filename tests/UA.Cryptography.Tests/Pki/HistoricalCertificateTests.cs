using Org.BouncyCastle.X509;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Gost;

namespace UA.Cryptography.Tests.Pki;

/// <summary>
/// Public certificates of Ukrainian certification authorities issued in 2005 – 2015 (expired; see
/// TestData/certificates/historical/README.md). Every signature is checked with this library only: GOST 34.311 with
/// the issuer's DKE over the TBS part, point decompression (6.10) and DSTU 4145 verification through the public
/// <see cref="Dstu4145Signer.VerifyMessage"/> API. BouncyCastle only splits the DER.
/// </summary>
public class HistoricalCertificateTests
{
    private static X509Certificate Load(string name) =>
        UaPki.ParseCertificate(File.ReadAllBytes(Path.Combine(TestFiles.HistoricalCertificates, name)));

    [Theory]
    [InlineData("bitis-root-2009.crt", "bitis-root-2009.crt", 257)] // self-signed root, named curve
    [InlineData("bitis-corp-2009.crt", "bitis-root-2009.crt", 257)]
    [InlineData("czo-root-2005.crt", "czo-root-2005.crt", 431)]     // the Central CA of 2005, explicit curve
    [InlineData("ucc-ca-2010.crt", "czo-root-2005.crt", 431)]
    [InlineData("ucc-tsp-2010.crt", "ucc-ca-2010.crt", 257)]
    public void CertificateSignatureVerifies(string subject, string issuer, int m)
    {
        X509Certificate certificate = Load(subject);
        Assert.Equal(Oids.Dstu4145WithGost34311, certificate.SigAlgOid);
        var (parameters, publicKey, dke) = UaPki.ReadPublicKey(Load(issuer));
        Assert.Equal(m, parameters.Field.M);

        // The signature value is an OCTET STRING with D (5.10) in little-endian byte order.
        byte[] signature = UaPki.Reverse(UaPki.UnwrapSignature(certificate.GetSignature()));

        var signer = new Dstu4145Signer(parameters);
        using Gost34311 hash = Gost34311.FromDke(dke!);
        Assert.True(signer.VerifyMessage(publicKey, certificate.GetTbsCertificate(), signature, hash));

        // A single changed bit of the signed data breaks it.
        byte[] tbs = certificate.GetTbsCertificate();
        tbs[tbs.Length / 2] ^= 1;
        Assert.False(signer.VerifyMessage(publicKey, tbs, signature, hash));
    }
}
