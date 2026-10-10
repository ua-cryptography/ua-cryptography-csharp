using UA.Cryptography.Cli;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.X509;

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

    [Theory]
    [InlineData("cades", "CAdES-X Long", "content")]
    [InlineData("asic-e", "XAdES-B-LT", "doc.txt")]
    public void IniReportHoldsEveryDetail(string format, string level, string reference)
    {
        Hierarchy pki = Hierarchy.Shared;
        using var server = new LocalPkiServer(pki);
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);
        File.WriteAllBytes(P("signer.jks"), store.Save(Password));
        File.WriteAllBytes(P("root.cer"), pki.Root.Certificate.GetEncoded());
        string document = Document();
        Assert.Equal(UaSign.Valid, Run("sign", "--keystore", P("signer.jks"), "--password", Password, "--format", format, "--level", "LT",
            "--in", document, "--out", P("signed"), "--tsa", server.TsaUrl, "--ocsp", server.OcspUrl).Code);

        var (code, output) = Run("verify", "--in", P("signed"), "--data", document, "--trust", P("root.cer"), "--format", "ini", "--report", P("report.ini"));
        Assert.True(code == UaSign.Valid, output);
        Dictionary<string, Dictionary<string, string>> ini = ParseIni(output);

        Assert.Equal("VALID", ini["summary"]["result"]);
        Assert.Equal("0", ini["summary"]["failures"]);
        Dictionary<string, string> signature = ini["signature.1"];
        Assert.Equal(level, signature["level"]);
        Assert.Equal("DSTU 7564-256 (1.2.804.2.1.1.1.1.2.2.1)", signature["digest_algorithm"]);
        Assert.StartsWith("DSTU 4145 with DSTU 7564-256 (", signature["signature_algorithm"], StringComparison.Ordinal);
        Assert.Equal(signature["timestamp_time"], signature["validation_time"]);

        Certificate signer = pki.Signer.Certificate.ToPki();
        Assert.Equal(signer.Subject.ToString(), ini["signature.1.signer"]["subject"]);
        Assert.Equal(Report.Serial(signer.SerialNumber), ini["signature.1.signer"]["serial"]);
        Assert.Equal(reference, ini["signature.1.reference.1"]["name"]);
        Assert.Equal(Convert.ToHexString(UaPki.Hash(Oids.Dstu7564_256, File.ReadAllBytes(document))), ini["signature.1.reference.1"]["digest"]);
        Assert.Equal("signature time-stamp", ini["signature.1.timestamp.1"]["kind"]);
        Assert.Equal(signature["timestamp_time"], ini["signature.1.timestamp.1"]["time"]);
        Assert.StartsWith("CN=Test TSP Server,", ini["signature.1.timestamp.1"]["authority"], StringComparison.Ordinal);

        // The signer's path up to the root, and a "good" embedded response for the signer and for the issuing CA.
        Dictionary<string, string> path = ini.Where(s => s.Key.StartsWith("signature.1.path.", StringComparison.Ordinal)).Select(s => s.Value).Single(p => p["for"] == "signer");
        Assert.Equal(PkiLayer.Root(pki).Subject.ToString(), path["certificate.3"]);
        List<Dictionary<string, string>> ocsp = ini.Where(s => s.Key.StartsWith("signature.1.ocsp.", StringComparison.Ordinal)).Select(s => s.Value).ToList();
        Assert.Equal(2, ocsp.Count(o => o["path"] == "signer" && o["status"] == "good" && o["source"] == "embedded"));
        Assert.DoesNotContain(ini["signature.1.checks"].Values, c => c.StartsWith("FAIL | ", StringComparison.Ordinal));
        Assert.Equal(signature["warnings"], ini["signature.1.checks"].Values.Count(c => c.StartsWith("WARN | ", StringComparison.Ordinal)).ToString(System.Globalization.CultureInfo.InvariantCulture));

        // --report writes the same report (except the time of verification) in UTF-8 without a BOM.
        byte[] file = File.ReadAllBytes(P("report.ini"));
        Assert.NotEqual(0xEF, file[0]);
        static string WithoutTime(string text) => string.Join("\n", text.ReplaceLineEndings("\n").Split('\n').Where(l => !l.StartsWith("verified_at=", StringComparison.Ordinal)));
        Assert.Equal(WithoutTime(output), WithoutTime(System.Text.Encoding.UTF8.GetString(file)));
    }

    [Fact]
    public void ReportFormatIsChecked()
    {
        string document = Document();
        var (code, output) = Run("verify", "--in", document, "--format", "json");
        Assert.Equal(UaSign.Error, code);
        Assert.Contains("--format must be text or ini", output, StringComparison.Ordinal);
    }

    private static Dictionary<string, Dictionary<string, string>> ParseIni(string text)
    {
        var sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        Dictionary<string, string>? current = null;
        foreach (string line in text.ReplaceLineEndings("\n").Split('\n'))
        {
            if (line.Length == 0 || line.StartsWith(';'))
                continue;
            if (line.StartsWith('['))
            {
                sections.Add(line[1..^1], current = new Dictionary<string, string>(StringComparer.Ordinal));
                continue;
            }
            int eq = line.IndexOf('=');
            Assert.True(current is not null && eq > 0, $"Not an INI line: {line}");
            current.Add(line[..eq], line[(eq + 1)..]);
        }
        return sections;
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

        // Level B carries only the signer's certificate: without the CA the output says how to get it.
        var (code, output) = Run("verify", "--in", document + ".p7s");
        Assert.Equal(UaSign.Valid, code);
        Assert.Contains("Hint: certificates are missing", output, StringComparison.Ordinal);

        // The synthetic certificates name no responder, so --online has nobody to ask: the warning stays.
        File.WriteAllBytes(P("ca.cer"), pki.IssuingCa.Certificate.GetEncoded());
        (code, output) = Run("verify", "--in", document + ".p7s", "--online", "--certs", P("ca.cer"));
        Assert.Equal(UaSign.Valid, code);
        Assert.Contains("[WARN] signer: revocation of 'Test Signer'", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Hint:", output, StringComparison.Ordinal);
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
