using UA.Cryptography.Cli;
using UA.Cryptography.Pki.KeyStore;

namespace UA.Cryptography.Tests.Cli;

/// <summary>
/// The ua-sign command line end to end, in process: key generation, signing in every format and level, verification
/// with its exit codes, and the usage errors. Levels T and LT go through HTTP to <see cref="LocalPkiServer"/>.
/// </summary>
public sealed class UaSignTests : IDisposable
{
    private const string Password = "test password";
    private readonly string _dir = Directory.CreateTempSubdirectory("ua-sign-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string P(string name) => Path.Combine(_dir, name);

    private static (int Code, string Output) Run(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        int code = UaSign.Run(args, output, error);
        return (code, output + error.ToString());
    }

    private string Keygen(string name = "key.jks", params string[] extra)
    {
        var (code, output) = Run(["keygen", "--keystore", P(name), "--subject", "CN=CLI Signer,O=UA Cryptography Tests,C=UA",
            "--password", Password, "--cert", P(name + ".cer"), .. extra]);
        Assert.True(code == UaSign.Valid, output);
        return P(name);
    }

    private string Document(string name = "doc.txt", string text = "Підписаний документ\n")
    {
        File.WriteAllText(P(name), text);
        return P(name);
    }

    [Theory]
    [InlineData("cades", "dstu7564")]
    [InlineData("cades", "gost34311")]
    [InlineData("xades", "dstu7564")]
    [InlineData("xades", "gost34311")]
    [InlineData("asic-s", "dstu7564")]
    [InlineData("asic-e", "dstu7564")]
    public void SignAndVerifyEachFormat(string format, string hash)
    {
        string keystore = Keygen();
        string document = Document();
        var (code, output) = Run("sign", "--keystore", keystore, "--password", Password, "--format", format, "--hash", hash, "--in", document);
        Assert.True(code == UaSign.Valid, output);
        string signed = Directory.GetFiles(_dir).Single(f => f != keystore && f != document && !f.EndsWith(".cer", StringComparison.Ordinal));

        (code, output) = Run("verify", "--in", signed, "--trust", keystore + ".cer");
        Assert.True(code == UaSign.Valid, output);
        Assert.Contains("Result: VALID", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[WARN] signer: trust", output, StringComparison.Ordinal);

        // Without a trusted root the result is still valid, with a warning.
        (code, output) = Run("verify", "--in", signed);
        Assert.Equal(UaSign.Valid, code);
        Assert.Contains("[WARN] signer: trust", output, StringComparison.Ordinal);
    }

    [Fact]
    public void DetachedCadesFindsItsDataAndExtractionWorks()
    {
        string keystore = Keygen();
        string document = Document();
        Assert.Equal(UaSign.Valid, Run("sign", "--keystore", keystore, "--password", Password, "--format", "cades", "--detached", "--in", document).Code);

        // doc.txt.p7s next to doc.txt: the data is found by name.
        var (code, output) = Run("verify", "--in", document + ".p7s", "--extract", P("out"));
        Assert.True(code == UaSign.Valid, output);
        Assert.Equal(File.ReadAllBytes(document), File.ReadAllBytes(P("out/doc.txt")));

        // Other data given explicitly: invalid.
        string other = Document("other.txt", "Інший документ\n");
        Assert.Equal(UaSign.Invalid, Run("verify", "--in", document + ".p7s", "--data", other).Code);
    }

    [Fact]
    public void SeveralFilesInXadesAndAsicE()
    {
        string keystore = Keygen();
        string a = Document("a.txt", "A");
        string b = Document("b.txt", "B");
        Assert.Equal(UaSign.Valid, Run("sign", "--keystore", keystore, "--password", Password, "--format", "asic-e", "--in", a, "--in", b,
            "--out", P("both.asice")).Code);
        Assert.Equal(UaSign.Valid, Run("sign", "--keystore", keystore, "--password", Password, "--format", "xades", "--in", a, "--in", b,
            "--out", P("both.xml")).Code);

        Assert.Equal(UaSign.Valid, Run("verify", "--in", P("both.asice")).Code);
        Assert.Equal(UaSign.Valid, Run("verify", "--in", P("both.xml")).Code); // a.txt and b.txt are next to it
        File.WriteAllText(b, "changed");
        var (code, output) = Run("verify", "--in", P("both.xml"));
        Assert.Equal(UaSign.Invalid, code);
        Assert.Contains("[FAIL] reference 'b.txt'", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ReferencesOutsideTheSignatureDirectoryAreNotFollowed()
    {
        string keystore = Keygen();
        var signer = UA.Cryptography.Pki.SigningKey.FromJks(JksKeyStore.Load(File.ReadAllBytes(keystore), Password), Password);
        byte[] outside = "outside"u8.ToArray();
        File.WriteAllBytes(P("outside.txt"), outside);
        Directory.CreateDirectory(P("inner"));
        File.WriteAllBytes(P("inner/sig.xml"),
            new UA.Cryptography.Pki.Xades.XadesSigner(signer).SignToBytes([new("../outside.txt", outside)]));

        var (code, output) = Run("verify", "--in", P("inner/sig.xml"));
        Assert.Equal(UaSign.Invalid, code);
        Assert.Contains("the referenced file was not given", output, StringComparison.Ordinal);
        Assert.Equal(UaSign.Valid, Run("verify", "--in", P("inner/sig.xml"), "--data", P("outside.txt")).Code);
    }

    [Fact]
    public void TamperedSignatureIsInvalid()
    {
        string keystore = Keygen();
        string document = Document();
        Run("sign", "--keystore", keystore, "--password", Password, "--format", "cades", "--in", document);
        byte[] signature = File.ReadAllBytes(document + ".p7s");
        int offset = signature.AsSpan().IndexOf(File.ReadAllBytes(document));
        signature[offset] ^= 1;
        File.WriteAllBytes(P("tampered.p7s"), signature);
        var (code, output) = Run("verify", "--in", P("tampered.p7s"));
        Assert.Equal(UaSign.Invalid, code);
        Assert.Contains("Result: INVALID", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("cades", "T")]
    [InlineData("cades", "LT")]
    [InlineData("asic-s", "LT")]
    [InlineData("xades", "T")]
    [InlineData("asic-e", "LT")]
    public void HigherLevelsUseTheTimeStampingAndOcspServices(string format, string level)
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);

        // The hierarchy's signer in a JKS, with its full chain, as a bank would issue it.
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);
        File.WriteAllBytes(P("signer.jks"), store.Save(Password));
        File.WriteAllBytes(P("root.cer"), pki.Root.Certificate.GetEncoded());
        File.WriteAllBytes(P("ca.cer"), pki.IssuingCa.Certificate.GetEncoded());
        string document = Document();

        var (code, output) = Run("sign", "--keystore", P("signer.jks"), "--password", Password, "--format", format, "--level", level,
            "--in", document, "--out", P("signed"), "--tsa", server.TsaUrl, "--ocsp", server.OcspUrl);
        Assert.True(code == UaSign.Valid, output);
        Assert.True(server.TimeStampRequests >= 1);
        Assert.Equal(level == "LT" ? 2 : 0, server.OcspRequests);

        // Levels B and T carry only the signer's certificate: the CA comes from --certs.
        (code, output) = Run("verify", "--in", P("signed"), "--data", document, "--trust", P("root.cer"), "--certs", P("ca.cer"));
        Assert.True(code == UaSign.Valid, output);
        Assert.Contains("Time-stamp:", output, StringComparison.Ordinal);
        if (level == "LT")
        {
            Assert.Contains("[ OK ] signer: revocation of 'Test Signer': good", output, StringComparison.Ordinal);
            Assert.Contains("[ OK ] signer: revocation of 'Test Issuing CA': good", output, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void OnlineVerificationWithoutAResponderKeepsTheWarning()
    {
        Hierarchy pki = Hierarchy.Shared;
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);
        File.WriteAllBytes(P("signer.jks"), store.Save(Password));
        string document = Document();
        Assert.Equal(UaSign.Valid, Run("sign", "--keystore", P("signer.jks"), "--password", Password, "--format", "cades", "--in", document).Code);

        // The synthetic certificates name no responder, so --online has nobody to ask: the warning stays.
        File.WriteAllBytes(P("ca.cer"), pki.IssuingCa.Certificate.GetEncoded());
        var (code, output) = Run("verify", "--in", document + ".p7s", "--online", "--certs", P("ca.cer"));
        Assert.Equal(UaSign.Valid, code);
        Assert.Contains("[WARN] signer: revocation of 'Test Signer'", output, StringComparison.Ordinal);
    }

    [Fact]
    public void InfoListsTheKeyStore()
    {
        string keystore = Keygen("info.jks", "--curve", "431", "--alias", "my key");
        var (code, output) = Run("info", "--keystore", keystore, "--password", Password);
        Assert.True(code == UaSign.Valid, output);
        Assert.Contains("[my key] private key", output, StringComparison.Ordinal);
        Assert.Contains("PB m = 431", output, StringComparison.Ordinal);

        (code, output) = Run("info", "--cert", TestFiles.Path("certificates", "intermediates", "dia-knedp.cer"));
        Assert.Equal(UaSign.Valid, code);
        Assert.Contains("OCSP http", output, StringComparison.Ordinal);
    }

    [Fact]
    public void PasswordsComeFromEnvironmentAndFiles()
    {
        string keystore = Keygen();
        File.WriteAllText(P("password.txt"), Password + "\n");
        Assert.Equal(UaSign.Valid, Run("info", "--keystore", keystore, "--password-file", P("password.txt")).Code);

        string variable = "UA_SIGN_TEST_PASSWORD_" + Environment.ProcessId;
        Environment.SetEnvironmentVariable(variable, Password);
        try
        {
            Assert.Equal(UaSign.Valid, Run("info", "--keystore", keystore, "--password-env", variable).Code);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
        var (code, output) = Run("info", "--keystore", keystore, "--password", "wrong");
        Assert.Equal(UaSign.Error, code);
        Assert.Contains("wrong password", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("sign", "--format", "pdf", "--in", "x")]
    [InlineData("sign", "--format", "cades")]
    [InlineData("sign", "--format", "xades", "--in", "a", "--detached")]
    [InlineData("verify", "--unknown")]
    [InlineData("verify", "--in")]
    [InlineData("keygen", "--keystore", "k.jks", "--subject", "CN=x", "--curve", "256", "--password", "p")]
    public void UsageErrorsExitWithTwo(params string[] args) => Assert.Equal(UaSign.Error, Run(args).Code);

    [Fact]
    public void ExistingFilesAreNotOverwrittenWithoutForce()
    {
        string keystore = Keygen();
        Assert.Equal(UaSign.Error, Run("keygen", "--keystore", keystore, "--subject", "CN=x", "--password", Password).Code);
        Assert.Equal(UaSign.Valid, Run("keygen", "--keystore", keystore, "--subject", "CN=x", "--password", Password, "--force").Code);
        Assert.Equal(UaSign.Valid, Run("--help").Code);
        Assert.Equal(UaSign.Valid, Run("sign", "--help").Code);
    }
}
