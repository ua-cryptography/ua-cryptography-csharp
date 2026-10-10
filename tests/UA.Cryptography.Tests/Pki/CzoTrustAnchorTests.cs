using UA.Cryptography.Math;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Pki;

/// <summary>
/// The current trust anchors: self-signed DSTU 4145 roots of Ukraine's Central Certification Authority
/// (Центральний засвідчувальний орган) from the official bundle at czo.gov.ua, and the root of the National Bank's
/// certification centre that banks' providers are certified under. Public certificates. All of them use the polynomial
/// basis with m = 431; the national PKI does not use the optimal normal basis.
/// </summary>
public class CzoTrustAnchorTests
{
    /// <summary>The CZO roots and the NBU root, as paths relative to the certificates folder.</summary>
    public static TheoryData<string> Roots => new(new[] { TestFiles.CzoRoots, TestFiles.NbuRoots }
        .SelectMany(d => Directory.GetFiles(d, "*.cer"))
        .Select(p => Path.GetRelativePath(TestFiles.Path("certificates"), p))
        .Order());

    private static X509Certificate Load(string name) => UaPki.ParseCertificate(File.ReadAllBytes(TestFiles.Path("certificates", name)));

    [Fact]
    public void TrustAnchorsArePresent() => Assert.NotEmpty(Roots);

    [Theory]
    [MemberData(nameof(Roots))]
    public void RootIsSelfSignedPolynomialAndVerifies(string name)
    {
        X509Certificate root = Load(name);
        Assert.True(root.SubjectDN.Equivalent(root.IssuerDN));

        var (parameters, publicKey, dke) = UaPki.ReadPublicKey(root);
        Assert.IsType<PolynomialBasisField>(parameters.Field);
        Assert.Equal(431, parameters.Field.M);

        // GOST 34.311 (older roots, with the root's DKE) or DSTU 7564-256 (the 2036 root), per the signature algorithm.
        Assert.True(UaPki.VerifyCertificate(root, root));

        byte[] tbs = root.GetTbsCertificate();
        tbs[tbs.Length / 2] ^= 1;
        byte[] hash = UaPki.Hash(UaPki.HashOf(root.SigAlgOid), tbs, dke);
        Assert.False(UaPki.VerifyDstu4145(parameters, publicKey, hash, UaPki.UnwrapSignature(root.GetSignature())));
    }
}
