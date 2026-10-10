using System.Security.Cryptography;
using System.Text;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Asic;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using UA.Cryptography.Pki.Xades;

namespace UA.Cryptography.Cli;

/// <summary>
/// ua-sign: DSTU 4145 keys in JKS, signing and verification in CAdES, XAdES, ASiC-S and ASiC-E. Exit codes: 0 — done /
/// the signature is valid, 1 — the signature is invalid, 2 — a usage or processing error.
/// </summary>
internal static class UaSign
{
    public const int Valid = 0;
    public const int Invalid = 1;
    public const int Error = 2;

    private const string Usage = """
        ua-sign — DSTU 4145 signatures of the Ukrainian PKI (CAdES, XAdES, ASiC-S, ASiC-E) with keys in JKS.

        Commands:
          keygen   create a key store with a new DSTU 4145 key and a self-signed certificate
          info     show the entries of a key store or the contents of certificates
          sign     sign files
          verify   verify a signature and show every check

        Run 'ua-sign <command> --help' for the options of a command.
        Exit codes: 0 done / valid, 1 invalid signature, 2 error.
        """;

    private const string PasswordHelp = """
          --password VALUE          the key store password (visible to other processes; prefer the next two)
          --password-env NAME       read the password from an environment variable
          --password-file PATH      read the password from the first line of a file
                                    (without these options the password is asked at the terminal)
        """;

    private static readonly Dictionary<string, (string Help, string[] Options, string[] Flags, Func<Arguments, TextWriter, int> Run)> Commands = new()
    {
        ["keygen"] = ("""
            ua-sign keygen --keystore PATH --subject DN [options]

              --keystore PATH           the JKS file to create
              --subject DN              certificate subject, e.g. "CN=Name,O=Organization,C=UA"
              --alias NAME              entry name (default: key)
              --curve M                 curve of table Г.1 of DSTU 4145: 163 167 173 179 191 233 257 307 367 431 (default: 257)
              --days N                  certificate validity in days (default: 365)
              --signature-hash NAME     hash of the certificate signature: dstu7564 (default) or gost34311
              --cert PATH               also write the certificate (DER) to this file
              --force                   overwrite existing files
            """ + PasswordHelp, ["keystore", "subject", "alias", "curve", "days", "signature-hash", "cert", .. Passwords.Options], ["force"], Keygen),

        ["info"] = ("""
            ua-sign info (--keystore PATH | --cert PATH...)

              --keystore PATH           list the entries of a JKS key store (asks for the password)
              --cert PATH               show a certificate (DER, PEM or a .p7b bundle); repeatable
            """ + PasswordHelp, ["keystore", "cert", .. Passwords.Options], [], Info),

        ["sign"] = ("""
            ua-sign sign --keystore PATH --format FORMAT --in FILE [options]

              --keystore PATH           JKS key store with the signing key
              --alias NAME              the key to use when the store holds several
              --format FORMAT           cades   CMS signature (.p7s), enveloped or with --detached
                                        xades   detached XML signature (.xml) next to the files
                                        asic-s  ZIP container with the file and a detached CAdES (.asics)
                                        asic-e  ZIP container with the files and a XAdES signature (.asice)
              --in FILE                 the file to sign; repeatable for xades and asic-e
              --out FILE                the result (default: the input name plus the format's extension)
              --level LEVEL             B (default), T (+ time-stamp) or LT (+ certificates and OCSP:
                                        XAdES-B-LT, CAdES-X Long)
              --hash NAME               dstu7564 (default, DSTU 7564-256) or gost34311
              --detached                cades: do not include the data in the signature
              --content-timestamp       cades: also time-stamp the data itself (needs a time-stamping service)
              --tsa URL                 time-stamping service (default: the one named in the signer's certificate)
              --ocsp URL                OCSP responder for every certificate (default: from each certificate)
              --certs FILE              CA certificates to complete the signer's chain; repeatable
              --force                   overwrite an existing output file
            """ + PasswordHelp,
            ["keystore", "alias", "format", "in", "out", "level", "hash", "tsa", "ocsp", "certs", .. Passwords.Options],
            ["detached", "content-timestamp", "force"], Sign),

        ["verify"] = ("""
            ua-sign verify --in SIGNATURE [options]

              --in FILE                 .p7s, .xml, .asics or .asice (the format is recognised by the content)
              --data FILE               the signed file of a detached signature; repeatable for XAdES
                                        (default: next to the signature, by the name the signature uses)
              --trust FILE              trusted root certificates (DER, PEM bundle, .p7b); repeatable
              --certs FILE              more certificates to complete chains; repeatable
              --online                  ask OCSP responders and download missing CA certificates
              --extract DIR             write the signed content into this directory
              --quiet                   print only the summary
              --format text|ini         text (default) or an INI report with every detail: algorithms, signer,
                                        digests, time-stamps, certificate paths, OCSP statuses and checks
              --report FILE             also write the INI report to FILE (UTF-8)
            """, ["in", "data", "trust", "certs", "extract", "format", "report"], ["online", "quiet"], Verify),
    };

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h" or "help")
        {
            output.WriteLine(Usage);
            return args.Length == 0 ? Error : Valid;
        }
        if (!Commands.TryGetValue(args[0], out var command))
        {
            error.WriteLine($"Unknown command '{args[0]}'.");
            error.WriteLine(Usage);
            return Error;
        }
        if (args.Skip(1).Any(a => a is "--help" or "-h"))
        {
            output.WriteLine(command.Help);
            return Valid;
        }
        try
        {
            return command.Run(new Arguments(args.Skip(1), command.Options, command.Flags), output);
        }
        catch (UsageException e)
        {
            error.WriteLine($"error: {e.Message}");
            error.WriteLine();
            error.WriteLine(command.Help);
            return Error;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException
            or NotSupportedException or ArgumentException or InvalidOperationException or HttpRequestException or TaskCanceledException
            or FormatException or System.Xml.XmlException)
        {
            error.WriteLine($"error: {e.Message}");
            return Error;
        }
    }

    // ---- keygen ----------------------------------------------------------------------------------------------

    private static int Keygen(Arguments args, TextWriter output)
    {
        string path = args.Required("keystore");
        DistinguishedName subject = DistinguishedName.Parse(args.Required("subject"));
        string alias = args.Optional("alias") ?? "key";
        int m = args.Int("curve", 257);
        if (!Dstu4145NamedCurves.PolynomialDegrees.Contains(m))
            throw new UsageException($"--curve {m}: table Г.1 has curves {string.Join(" ", Dstu4145NamedCurves.PolynomialDegrees)}.");
        int days = args.Int("days", 365);
        string signatureHash = PkiAlgorithms.ParseHashName(args.Optional("signature-hash") ?? "dstu7564");
        string? certPath = args.Optional("cert");
        CheckWritable(path, args.Flag("force"));
        if (certPath is not null)
            CheckWritable(certPath, args.Flag("force"));
        string password = Passwords.Read(args, confirm: true);
        if (password.Length == 0)
            throw new UsageException("The password must not be empty.");

        Dstu4145PrivateKey key = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(m));
        Certificate certificate = new CertificateBuilder(subject, key.PublicKey)
        {
            NotAfter = DateTimeOffset.UtcNow.AddDays(days),
            SignatureAlgorithm = PkiAlgorithms.SignatureAlgorithmFor(signatureHash),
        }
            .AddBasicConstraints(isCa: false)
            .AddKeyUsage(KeyUsageFlags.DigitalSignature | KeyUsageFlags.NonRepudiation)
            .AddSubjectKeyIdentifier()
            .SelfSign(key);

        var store = new JksKeyStore();
        store.AddPrivateKey(alias, key, [certificate], password);
        File.WriteAllBytes(path, store.Save(password));
        if (certPath is not null)
            File.WriteAllBytes(certPath, certificate.Encoded);

        output.WriteLine($"Key store:   {path}");
        output.WriteLine($"Alias:       {alias}");
        output.WriteLine($"Key:         DSTU 4145, polynomial basis, m = {m} (table Г.1)");
        DescribeCertificate(certificate, output, "Certificate: ");
        if (certPath is not null)
            output.WriteLine($"Written:     {certPath}");
        output.WriteLine("The certificate is self-signed: signatures verify, but they are not qualified.");
        return Valid;
    }

    // ---- info ------------------------------------------------------------------------------------------------

    private static int Info(Arguments args, TextWriter output)
    {
        string? keystore = args.Optional("keystore");
        IReadOnlyList<string> certs = args.All("cert");
        if (keystore is null && certs.Count == 0)
            throw new UsageException("Give --keystore or --cert.");
        if (keystore is not null)
        {
            byte[] data = File.ReadAllBytes(keystore);
            JksKeyStore store = JksKeyStore.Load(data, Passwords.Read(args));
            output.WriteLine($"Key store {keystore}: {store.Entries.Count} entries");
            foreach (JksEntry entry in store.Entries)
            {
                output.WriteLine();
                if (entry is JksPrivateKeyEntry key)
                {
                    output.WriteLine($"[{entry.Alias}] private key, created {entry.Created:yyyy-MM-dd}, chain of {key.Chain.Count}");
                    foreach (Certificate c in key.Chain)
                        DescribeCertificate(c, output, "  ");
                }
                else if (entry is JksTrustedCertificateEntry trusted)
                {
                    output.WriteLine($"[{entry.Alias}] trusted certificate");
                    DescribeCertificate(trusted.Certificate, output, "  ");
                }
            }
        }
        foreach (string path in certs)
        {
            foreach (Certificate c in CertificateFiles.Load(path))
            {
                output.WriteLine($"{path}:");
                DescribeCertificate(c, output, "  ");
                if (c.IsSelfIssued)
                    output.WriteLine($"  Self-signature: {(c.IsSignedBy(c) ? "valid" : "INVALID")}");
            }
        }
        return Valid;
    }

    private static void DescribeCertificate(Certificate c, TextWriter output, string indent)
    {
        string pad = new(' ', indent.Length);
        output.WriteLine($"{indent}{c.Subject}");
        output.WriteLine($"{pad}issuer {c.Issuer}");
        output.WriteLine($"{pad}serial {Report.Serial(c.SerialNumber)}, valid {c.NotBefore:yyyy-MM-dd} – {c.NotAfter:yyyy-MM-dd}");
        output.WriteLine($"{pad}{Report.Key(c)}");
        foreach (string url in c.OcspUrls)
            output.WriteLine($"{pad}OCSP {url}");
        foreach (string url in c.TimeStampUrls)
            output.WriteLine($"{pad}TSP  {url}");
    }

    // ---- sign ------------------------------------------------------------------------------------------------

    private static int Sign(Arguments args, TextWriter output)
    {
        string format = args.Required("format").ToLowerInvariant();
        if (format is not ("cades" or "xades" or "asic-s" or "asic-e"))
            throw new UsageException($"--format {format}: expected cades, xades, asic-s or asic-e.");
        IReadOnlyList<string> inputs = args.All("in");
        if (inputs.Count == 0)
            throw new UsageException("--in is required.");
        if (inputs.Count > 1 && format is ("cades" or "asic-s"))
            throw new UsageException($"{format} signs one file; use xades or asic-e for several.");
        if (args.Flag("detached") && format != "cades")
            throw new UsageException("--detached applies to cades only (asic-s and xades are always detached).");
        if (args.Flag("content-timestamp") && format is not ("cades" or "asic-s"))
            throw new UsageException("--content-timestamp applies to cades and asic-s.");

        SignatureLevel level = (args.Optional("level") ?? "B").ToUpperInvariant() switch
        {
            "B" => SignatureLevel.B,
            "T" => SignatureLevel.T,
            "LT" or "XL" or "X-LONG" => SignatureLevel.LT,
            string other => throw new UsageException($"--level {other}: expected B, T or LT."),
        };
        string hashOid = PkiAlgorithms.ParseHashName(args.Optional("hash") ?? "dstu7564");
        string outPath = args.Optional("out") ?? inputs[0] + format switch
        {
            "cades" => ".p7s",
            "xades" => ".xml",
            "asic-s" => ".asics",
            _ => ".asice",
        };
        CheckWritable(outPath, args.Flag("force"));
        List<SignedFile> files = inputs.Select(p => new SignedFile(Path.GetFileName(p), File.ReadAllBytes(p))).ToList();
        if (files.Select(f => f.Name).Distinct(StringComparer.Ordinal).Count() != files.Count)
            throw new UsageException("Two inputs have the same file name.");

        byte[] keystore = File.ReadAllBytes(args.Required("keystore"));
        string password = Passwords.Read(args);
        SigningKey signer = SigningKey.FromJks(JksKeyStore.Load(keystore, password), password, args.Optional("alias"));
        List<Certificate> extra = args.All("certs").SelectMany(CertificateFiles.Load).ToList();

        bool needsTsa = level >= SignatureLevel.T || args.Flag("content-timestamp");
        string? tsa = args.Optional("tsa") ?? signer.Chain.SelectMany(c => c.TimeStampUrls).FirstOrDefault();
        if (needsTsa && tsa is null)
            throw new UsageException("This level needs a time-stamping service: give --tsa URL (the certificate names none).");
        var services = new SignatureServices
        {
            TimeStamps = needsTsa ? new HttpTimeStampService(tsa!) : null,
            Ocsp = level >= SignatureLevel.LT ? new HttpOcspService(args.Optional("ocsp")) : null,
            Downloads = level >= SignatureLevel.LT ? new HttpCertificateSource() : null,
            ExtraCertificates = extra,
        };

        byte[] result = format switch
        {
            "cades" => new CadesSigner(signer, services).Sign(files[0].Content,
                new CadesOptions(hashOid, args.Flag("detached"), level, ContentTimeStamp: args.Flag("content-timestamp"))),
            "asic-s" => AsicContainer.CreateAsicS(files[0].Name, files[0].Content, new CadesSigner(signer, services).Sign(files[0].Content,
                new CadesOptions(hashOid, Detached: true, level, ContentTimeStamp: args.Flag("content-timestamp")))),
            "xades" => new XadesSigner(signer, services).SignToBytes(files, hashOid, level),
            _ => AsicContainer.CreateAsicE(files, new XadesSigner(signer, services).Sign(files, hashOid, level)),
        };
        File.WriteAllBytes(outPath, result);

        string levelName = format is "cades" or "asic-s"
            ? level switch { SignatureLevel.B => "CAdES-B", SignatureLevel.T => "CAdES-T", _ => "CAdES-X Long" }
            : $"XAdES-B-{level}";
        output.WriteLine($"Signed:  {string.Join(", ", inputs)}");
        output.WriteLine($"Signer:  {signer.Certificate.Subject}");
        output.WriteLine($"Format:  {format}, {levelName}, {PkiAlgorithms.HashName(hashOid)}{(args.Flag("detached") ? ", detached" : "")}");
        if (needsTsa)
            output.WriteLine($"TSA:     {tsa}");
        output.WriteLine($"Written: {outPath}");
        return Valid;
    }

    // ---- verify ----------------------------------------------------------------------------------------------

    private static int Verify(Arguments args, TextWriter output)
    {
        string path = args.Required("in");
        bool ini = (args.Optional("format") ?? "text") switch
        {
            "text" => false,
            "ini" => true,
            _ => throw new UsageException("--format must be text or ini."),
        };
        byte[] signature = File.ReadAllBytes(path);
        string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Dictionary<string, byte[]> data = args.All("data").ToDictionary(p => Path.GetFileName(p), File.ReadAllBytes, StringComparer.Ordinal);

        byte[]? Detached(string? name)
        {
            if (name is null)
            {
                // A detached CAdES: --data, else the signature's name without .p7s.
                if (data.Count == 1)
                    return data.Values.First();
                string implied = Path.ChangeExtension(Path.GetFullPath(path), null);
                return Path.GetExtension(path).Equals(".p7s", StringComparison.OrdinalIgnoreCase) && File.Exists(implied) ? File.ReadAllBytes(implied) : null;
            }
            string baseName = Path.GetFileName(name);
            if (data.TryGetValue(baseName, out byte[]? given))
                return given;
            if (data.Count == 1)
                return data.Values.First();
            // Only files below the signature's directory: a reference like "../../secret" is not followed.
            string candidate = Path.GetFullPath(Path.Combine(directory, name));
            return candidate.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.Ordinal) && File.Exists(candidate)
                ? File.ReadAllBytes(candidate)
                : null;
        }

        bool online = args.Flag("online");
        var options = new ValidationOptions
        {
            TrustAnchors = args.All("trust").SelectMany(CertificateFiles.Load).ToList(),
            ExtraCertificates = args.All("certs").SelectMany(CertificateFiles.Load).ToList(),
            OnlineOcsp = online ? new HttpOcspService() : null,
            Downloads = online ? new HttpCertificateSource() : null,
        };
        VerificationResult result = SignatureVerifier.Verify(signature, Detached, options);
        if (ini)
        {
            Report.WriteIni(path, result, output);
        }
        else
        {
            Report.Write(path, result, output, args.Flag("quiet"));
            if (!online && result.Signatures.SelectMany(r => r.Checks).Any(c => c.Status != CheckStatus.Passed
                && c.Details.Contains("is not available", StringComparison.Ordinal)))
                output.WriteLine("Hint: certificates are missing; --online downloads them from the certificates' caIssuers addresses, "
                    + "or give them with --certs.");
        }
        if (args.Optional("report") is { } reportPath)
        {
            using (var writer = new StreamWriter(reportPath, false, new UTF8Encoding(false)))
                Report.WriteIni(path, result, writer);
            if (!ini)
                output.WriteLine($"Report: {reportPath}");
        }

        if (args.Optional("extract") is { } extract)
        {
            Directory.CreateDirectory(extract);
            string root = Path.GetFullPath(extract);
            foreach ((string name, byte[] content) in result.SignedFiles)
            {
                string target = Path.GetFullPath(Path.Combine(root, name == "content" ? Path.GetFileNameWithoutExtension(path) : name));
                if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                    throw new InvalidDataException($"Refusing to extract '{name}' outside {extract}.");
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.WriteAllBytes(target, content);
                output.WriteLine(ini ? $"; extracted: {target}" : $"Extracted: {target}");
            }
        }
        return result.IsValid ? Valid : Invalid;
    }

    private static void CheckWritable(string path, bool force)
    {
        if (File.Exists(path) && !force)
            throw new UsageException($"{path} exists; add --force to overwrite it.");
    }
}
