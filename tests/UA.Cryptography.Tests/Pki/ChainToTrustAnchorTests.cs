using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Pki;

/// <summary>
/// Certificate chains that must (or must not) terminate at a trusted CZO root (<see cref="CzoTrustAnchorTests"/>),
/// every link verified with this library.
/// </summary>
public class ChainToTrustAnchorTests
{
    private static X509Certificate[] TrustedRoots() =>
        Directory.GetFiles(TestFiles.CzoRoots, "*.cer").Select(p => UaPki.ParseCertificate(File.ReadAllBytes(p))).ToArray();

    [Fact]
    public void DiiaIssuingCaChainsToTrustedCzoRoot()
    {
        X509Certificate intermediate = UaPki.ParseCertificate(File.ReadAllBytes(Path.Combine(TestFiles.Intermediates, "dia-knedp.cer")));
        X509Certificate[] trusted = TrustedRoots();
        Assert.True(UaPki.ChainsToTrusted(intermediate, trusted, trusted));
    }

    [Fact]
    public void PrivatBankIssuingCaChainsToTheNbuRootAndNotToCzo()
    {
        X509Certificate intermediate = UaPki.ParseCertificate(File.ReadAllBytes(Path.Combine(TestFiles.Intermediates, "privatbank-knedp.cer")));
        X509Certificate[] nbu = Directory.GetFiles(TestFiles.NbuRoots, "*.cer").Select(p => UaPki.ParseCertificate(File.ReadAllBytes(p))).ToArray();
        Assert.True(UaPki.ChainsToTrusted(intermediate, nbu, nbu));
        Assert.False(UaPki.ChainsToTrusted(intermediate, TrustedRoots(), TrustedRoots()));
    }

    [Fact]
    public void SyntheticChainIsRejectedByCzoTrust()
    {
        // A synthetic root and leaf verify among themselves but do not terminate at a trusted CZO root.
        Hierarchy pki = Hierarchy.Shared;
        Assert.True(UaPki.ChainsToTrusted(pki.Signer.Certificate, pki.SignerChain.ToList(), [pki.Root.Certificate]));
        Assert.False(UaPki.ChainsToTrusted(pki.Signer.Certificate, pki.SignerChain.ToList(), TrustedRoots()));
    }

    [Fact]
    public void ChainWithForeignIssuerIsRejected()
    {
        // Same issuer name, different key: the link does not verify.
        Hierarchy pki = Hierarchy.Shared;
        TestPki.TestIdentity impostor = TestPki.CreateSelfSigned(pki.Root.Certificate.SubjectDN.ToString());
        Assert.False(UaPki.ChainsToTrusted(pki.IssuingCa.Certificate, [impostor.Certificate], [impostor.Certificate]));
    }
}
