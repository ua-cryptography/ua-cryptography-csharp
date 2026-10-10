using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Tests.Pki.Validation;

/// <summary>
/// Certification paths: the real "Дія" CA up to a ЦЗО root, the synthetic hierarchy with OCSP, and the ways a path can
/// fail (untrusted root, expiry, a CA that is not a CA, an impostor with the issuer's name, a missing responder).
/// </summary>
public class PathValidationTests
{
    private static Certificate[] CzoRoots() => Directory.GetFiles(TestFiles.CzoRoots, "*.cer").Select(Certificate.Load).ToArray();

    private static VerificationReport Validate(Certificate leaf, IEnumerable<Certificate> pool, IReadOnlyCollection<OcspResponse> ocsp,
        ValidationOptions options, DateTimeOffset time)
    {
        var report = new VerificationReport("test");
        CertificatePathValidator.Validate(leaf, pool, ocsp, options, time, report, "path");
        return report;
    }

    [Fact]
    public void DiiaCaChainsToTheTrustedCzoRoot()
    {
        Certificate dia = Certificate.Load(TestFiles.Read("certificates", "intermediates", "dia-knedp.cer"));
        Certificate[] roots = CzoRoots();
        VerificationReport report = Validate(dia, [], [], new ValidationOptions { TrustAnchors = roots }, dia.NotBefore.AddDays(1));
        Assert.True(report.IsValid, string.Join("\n", report.Checks));
        Assert.Contains(report.Checks, c => c.Name == "path: trust" && c.Status == CheckStatus.Passed);

        // Without the roots the path stops at the CA itself.
        report = Validate(dia, [], [], new ValidationOptions(), dia.NotBefore.AddDays(1));
        Assert.Contains(report.Checks, c => c.Name == "path: trust" && c.Status == CheckStatus.Warning);
    }

    [Fact]
    public void SyntheticSignerWithOcspIsFullyValidated()
    {
        Hierarchy pki = Hierarchy.Shared;
        var ocsp = new PkiLayer.Ocsp(pki);
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Certificate root = PkiLayer.Root(pki);
        OcspResponse[] responses = [ocsp.GetResponse(signer, ca, "")!, ocsp.GetResponse(ca, root, "")!];

        VerificationReport report = Validate(signer, [ca], responses, new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow);
        Assert.True(report.IsValid, string.Join("\n", report.Checks));
        Assert.DoesNotContain(report.Checks, c => c.Status != CheckStatus.Passed);
        Assert.Equal(2, report.Checks.Count(c => c.Name.StartsWith("path: revocation", StringComparison.Ordinal)));

        // The same path asked online instead of from embedded responses.
        var online = new PkiLayer.Ocsp(pki);
        report = Validate(signer, [ca], [], new ValidationOptions { TrustAnchors = [root], OnlineOcsp = online }, DateTimeOffset.UtcNow);
        Assert.True(report.IsValid);
        Assert.Equal(2, online.Requests);

        // A response about another certificate does not count.
        report = Validate(signer, [ca], [responses[1]], new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: revocation of 'Test Signer'" && c.Status == CheckStatus.Warning);
    }

    [Fact]
    public void FailuresAreReported()
    {
        Hierarchy pki = Hierarchy.Shared;
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Certificate root = PkiLayer.Root(pki);

        // Untrusted: the synthetic root is not a ЦЗО root.
        VerificationReport report = Validate(signer, [ca, root], [], new ValidationOptions { TrustAnchors = CzoRoots() }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: trust" && c.Status == CheckStatus.Failed);

        // Expired at the validation time.
        report = Validate(signer, [ca], [], new ValidationOptions { TrustAnchors = [root] }, signer.NotAfter.AddDays(1));
        Assert.Contains(report.Checks, c => c.Name == "path: validity of 'Test Signer'" && c.Status == CheckStatus.Failed);

        // An impostor root with the same name does not verify the CA, so the path is incomplete.
        var impostorKey = Dstu4145PrivateKey.Generate(root.PublicKey.Domain);
        Certificate impostor = new CertificateBuilder(root.Subject, impostorKey.PublicKey).AddBasicConstraints(true).SelfSign(impostorKey);
        report = Validate(signer, [ca], [], new ValidationOptions { TrustAnchors = [impostor] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: trust" && c.Status == CheckStatus.Failed);

        // A certificate that issues another one without being a CA.
        var leafKey = Dstu4145PrivateKey.Generate(root.PublicKey.Domain);
        Certificate leaf = new CertificateBuilder(DistinguishedName.Parse("CN=Below a leaf"), leafKey.PublicKey).Issue(signer, pki.Signer.Key.ToPki());
        report = Validate(leaf, [signer, ca], [], new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: 'Test Signer'" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial()
    {
        // The "Дія" responder fills the CertID issuerKeyHash with zeros.
        Hierarchy pki = Hierarchy.Shared;
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Certificate root = PkiLayer.Root(pki);
        OcspResponse zero = OcspResponse.Load(OcspResponder.Encode(
            pki.IssuingCaOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate, zeroKeyHash: true)));
        Assert.True(zero.Responses.Single().IssuerKeyHash.All(b => b == 0));

        VerificationReport report = Validate(signer, [ca], [zero], new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: revocation of 'Test Signer'" && c.Status == CheckStatus.Passed);

        // The name hash and the serial number still have to match.
        Assert.NotNull(zero.Find(signer, ca));
        Assert.Null(zero.Find(signer, root));
        Assert.Null(zero.Find(ca, ca));

        // And the responder still has to be authorized by the issuer.
        OcspResponse foreign = OcspResponse.Load(OcspResponder.Encode(
            pki.RootOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate, zeroKeyHash: true)));
        report = Validate(signer, [ca], [foreign], new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: revocation of 'Test Signer'" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void OcspFromAnUnauthorizedResponderIsRejected()
    {
        // The root's responder answers about the signer, whose issuer is the issuing CA: not its responder.
        Hierarchy pki = Hierarchy.Shared;
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        OcspResponse foreign = OcspResponse.Load(OcspResponder.Encode(pki.RootOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate)));
        VerificationReport report = Validate(signer, [ca], [foreign], new ValidationOptions { TrustAnchors = [PkiLayer.Root(pki)] }, DateTimeOffset.UtcNow);
        Assert.Contains(report.Checks, c => c.Name == "path: revocation of 'Test Signer'" && c.Status == CheckStatus.Failed);
    }
}
