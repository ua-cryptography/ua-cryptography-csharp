using System.IO.Compression;
using UA.Cryptography.Cli;
using UA.Cryptography.Pki.KeyStore;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Signatures;

/// <summary>
/// The two provider formats of docs/provider-formats.md, end to end through ua-sign with keys in JKS: for each, a
/// signature made by ua-sign has the provider's profile (<see cref="PrivatBankSig"/>, <see cref="DiiaAsicE"/>, checked
/// independently of the package) and verifies, and a signature made the way the provider makes it verifies too.
/// The services — TSA, OCSP, the caIssuers bundle — are <see cref="LocalPkiServer"/>.
/// </summary>
public sealed class ProviderFormatTests : IDisposable
{
    private const string Password = "provider formats";
    private static readonly byte[] Document = "Документ для підпису\n"u8.ToArray();
    private readonly string _dir = Directory.CreateTempSubdirectory("provider-formats-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string P(string name) => Path.Combine(_dir, name);

    private static (int Code, string Output) Run(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        int code = UaSign.Run(args, output, error);
        return (code, output + error.ToString());
    }

    /// <summary>
    /// A customer's certificate as a bank issues it: by the hierarchy's issuing CA, naming the OCSP responder and the
    /// caIssuers bundle of <paramref name="server"/> in authorityInfoAccess.
    /// </summary>
    private static TestPki.TestIdentity BankCustomer(Hierarchy pki, LocalPkiServer server)
    {
        TestPki.TestIdentity customer = TestPki.Issue("CN=Test Bank Customer,O=UA Cryptography Tests,C=UA", pki.Signer.Key, pki.IssuingCa,
            signatureAlgorithm: Oids.Dstu4145WithDstu7564, ocspUrl: server.OcspUrl, caIssuersUrl: server.CaIssuersUrl);
        server.ExtraCertificates.Add(customer.Certificate);
        return customer;
    }

    private string WriteRoot(Hierarchy pki)
    {
        File.WriteAllBytes(P("root.cer"), pki.Root.Certificate.GetEncoded());
        return P("root.cer");
    }

    // ---- PrivatBank: CAdES-T, enveloped, .sig ----------------------------------------------------------------------

    [Theory]
    [InlineData("bank-issued")]
    [InlineData("keygen")]
    public void PrivatBankSigIsMadeByUaSignAndVerifies(string key)
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        File.WriteAllBytes(P("doc.txt"), Document);
        X509Certificate signer;
        string[] trust;
        if (key == "bank-issued")
        {
            // The key store as PrivatBank issues it: the chain root first, then the certificate of the key-agreement key.
            TestPki.TestIdentity customer = BankCustomer(pki, server);
            TestPki.TestIdentity agreement = TestPki.Issue("CN=Test Bank Customer,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(431),
                pki.IssuingCa, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
            var store = new JksKeyStore();
            store.AddPrivateKey("pb_sign", customer.Key.ToPki(),
                new[] { pki.Root.Certificate, pki.IssuingCa.Certificate, customer.Certificate, agreement.Certificate }.Select(c => c.ToPki()).ToList(),
                Password);
            File.WriteAllBytes(P("key.jks"), store.Save(Password));
            signer = customer.Certificate;
            trust = ["--trust", WriteRoot(pki), "--online"];
        }
        else
        {
            var (code, output) = Run("keygen", "--keystore", P("key.jks"), "--subject", "CN=Keygen Signer,O=UA Cryptography Tests,C=UA",
                "--password", Password, "--cert", P("key.cer"));
            Assert.True(code == UaSign.Valid, output);
            signer = UaPki.ParseCertificate(File.ReadAllBytes(P("key.cer")));
            // The key's own certificate for the signer, the hierarchy's root for the time-stamping service.
            trust = ["--trust", P("key.cer"), "--trust", WriteRoot(pki)];
        }

        var (signCode, signOutput) = Run("sign", "--keystore", P("key.jks"), "--password", Password, "--format", "cades", "--level", "T",
            "--in", P("doc.txt"), "--out", P("doc.txt.sig"), "--tsa", server.TsaUrl);
        Assert.True(signCode == UaSign.Valid, signOutput);
        PrivatBankSig.AssertProfile(File.ReadAllBytes(P("doc.txt.sig")), Document, signer);

        var (verifyCode, verifyOutput) = Run(["verify", "--in", P("doc.txt.sig"), .. trust]);
        Assert.True(verifyCode == UaSign.Valid, verifyOutput);
        Assert.DoesNotContain("[FAIL]", verifyOutput, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signature time-stamp: signature", verifyOutput, StringComparison.Ordinal);
        Assert.Contains("and so do its issuer and serial number", verifyOutput, StringComparison.Ordinal);
        if (key == "bank-issued")
            Assert.Contains("[ OK ] signer: revocation of 'Test Bank Customer': good, online response", verifyOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void PrivatBankSigAsTheBankMakesItVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        TestPki.TestIdentity customer = BankCustomer(pki, server);
        byte[] signature = PrivatBankSig.Build(Document, pki, customer);
        PrivatBankSig.AssertProfile(signature, Document, customer.Certificate);
        File.WriteAllBytes(P("doc.txt.sig"), signature);

        // Offline: neither the CA's nor the TSA's certificate is in the signature.
        var (code, output) = Run("verify", "--in", P("doc.txt.sig"));
        Assert.True(code == UaSign.Valid, output);
        Assert.Contains("[WARN] signature time-stamp: service certificate", output, StringComparison.Ordinal);
        Assert.Contains("Hint: certificates are missing", output, StringComparison.Ordinal);
        (code, output) = Run("verify", "--in", P("doc.txt.sig"), "--trust", WriteRoot(pki));
        Assert.Equal(UaSign.Invalid, code);
        Assert.Contains("[FAIL] signer: trust", output, StringComparison.Ordinal);

        // Online: the caIssuers bundle completes both, in one download; OCSP answers for the customer.
        (code, output) = Run("verify", "--in", P("doc.txt.sig"), "--trust", P("root.cer"), "--online");
        Assert.True(code == UaSign.Valid, output);
        Assert.DoesNotContain("[FAIL]", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signature time-stamp: signature", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signer: trust", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signer: revocation of 'Test Bank Customer': good", output, StringComparison.Ordinal);
        Assert.Equal(1, server.CaIssuersRequests);

        // The document inside is changed: invalid.
        int at = signature.AsSpan().IndexOf(Document);
        signature[at] ^= 1;
        File.WriteAllBytes(P("tampered.sig"), signature);
        Assert.Equal(UaSign.Invalid, Run("verify", "--in", P("tampered.sig"), "--trust", P("root.cer"), "--online").Code);
    }

    // ---- "Дія": ASiC-E with XAdES-B-LT ----------------------------------------------------------------------------

    [Fact]
    public void DiiaAsicEIsMadeByUaSignAndVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        File.WriteAllBytes(P("doc.txt"), Document);
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);
        File.WriteAllBytes(P("key.jks"), store.Save(Password));

        var (code, output) = Run("sign", "--keystore", P("key.jks"), "--password", Password, "--format", "asic-e", "--level", "LT",
            "--in", P("doc.txt"), "--out", P("doc.txt.asice"), "--tsa", server.TsaUrl, "--ocsp", server.OcspUrl);
        Assert.True(code == UaSign.Valid, output);
        DiiaAsicE.AssertProfile(File.ReadAllBytes(P("doc.txt.asice")), "doc.txt", Document, pki.Signer.Certificate, pki.IssuingCa.Certificate,
            ocspFor: pki.Signer.Certificate);

        // Offline, with the root only: everything the check needs is in the container.
        (code, output) = Run("verify", "--in", P("doc.txt.asice"), "--trust", WriteRoot(pki));
        Assert.True(code == UaSign.Valid, output);
        Assert.DoesNotContain("[FAIL]", output, StringComparison.Ordinal);
        Assert.Contains("XAdES-B-LT, detached, DSTU 7564-256", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signer: revocation of 'Test Signer': good, embedded", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signer: revocation of 'Test Issuing CA': good, embedded", output, StringComparison.Ordinal);
    }

    [Fact]
    public void DiiaAsicEAsDiiaMakesItVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] container = DiiaAsicE.Build(Document, "doc.txt", pki);
        DiiaAsicE.AssertProfile(container, "doc.txt", Document, pki.Signer.Certificate, pki.IssuingCa.Certificate, ocspFor: pki.Signer.Certificate);
        File.WriteAllBytes(P("doc.txt.asice"), container);

        var (code, output) = Run("verify", "--in", P("doc.txt.asice"), "--trust", WriteRoot(pki));
        Assert.True(code == UaSign.Valid, output);
        Assert.DoesNotContain("[FAIL]", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] manifest: lists all 1 data files", output, StringComparison.Ordinal);
        Assert.Contains("[ OK ] signature time-stamp: signature", output, StringComparison.Ordinal);
        // The response with a zero issuerKeyHash counts; "Дія" embeds none about its CA.
        Assert.Contains("[ OK ] signer: revocation of 'Test Signer': good, embedded", output, StringComparison.Ordinal);
        Assert.Contains("[WARN] signer: revocation of 'Test Issuing CA'", output, StringComparison.Ordinal);

        // The document in the container is changed: invalid.
        using (var zip = ZipFile.Open(P("doc.txt.asice"), ZipArchiveMode.Update))
        {
            zip.GetEntry("doc.txt")!.Delete();
            using Stream s = zip.CreateEntry("doc.txt").Open();
            s.Write("Інший документ\n"u8);
        }
        (code, output) = Run("verify", "--in", P("doc.txt.asice"), "--trust", P("root.cer"));
        Assert.Equal(UaSign.Invalid, code);
        Assert.Contains("[FAIL] reference 'doc.txt'", output, StringComparison.Ordinal);
    }
}
