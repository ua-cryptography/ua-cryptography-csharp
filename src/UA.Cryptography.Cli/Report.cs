using System.Globalization;
using System.Numerics;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Cli;

/// <summary>Prints a verification result: every signature, its signer and times, and each check.</summary>
internal static class Report
{
    public static void Write(string path, VerificationResult result, TextWriter output, bool quiet)
    {
        output.WriteLine($"File:      {path} — {result.Format}");
        foreach (VerificationReport report in result.Signatures)
        {
            output.WriteLine();
            output.WriteLine($"{report.Title}{(report.Format is null ? "" : $" — {report.Format}")}");
            if (report.Signer is { } signer)
            {
                output.WriteLine($"  Signer:     {signer.Subject}");
                output.WriteLine($"  Issuer:     {signer.Issuer}");
            }
            if (report.ClaimedSigningTime is { } claimed)
                output.WriteLine($"  Signed at:  {claimed:yyyy-MM-dd HH:mm:ss} UTC (claimed by the signer)");
            if (report.TimeStampTime is { } stamped)
                output.WriteLine($"  Time-stamp: {stamped:yyyy-MM-dd HH:mm:ss} UTC");
            foreach (VerificationCheck check in report.Checks)
            {
                if (quiet && check.Status == CheckStatus.Passed)
                    continue;
                string mark = check.Status switch
                {
                    CheckStatus.Passed => "[ OK ]",
                    CheckStatus.Warning => "[WARN]",
                    _ => "[FAIL]",
                };
                output.WriteLine($"  {mark} {check.Name}: {check.Details}");
            }
            output.WriteLine($"  => {(report.IsValid ? report.HasWarnings ? "valid, with warnings" : "valid" : "INVALID")}");
        }
        int warnings = result.Signatures.Sum(r => r.Checks.Count(c => c.Status == CheckStatus.Warning));
        output.WriteLine();
        output.WriteLine(result.IsValid
            ? $"Result: VALID{(warnings switch { 0 => "", 1 => " (1 warning)", _ => $" ({warnings} warnings)" })}"
            : "Result: INVALID");
    }

    /// <summary>
    /// Writes the result as INI: [summary], then for the container and each signature its properties, signer, signed
    /// references, time-stamps, certification paths, OCSP statuses and checks. Times are UTC in ISO 8601; digests and
    /// serial numbers are hex; algorithms are a name followed by the identifier in parentheses.
    /// </summary>
    public static void WriteIni(string path, VerificationResult result, TextWriter output)
    {
        void Section(string name)
        {
            output.WriteLine();
            output.WriteLine($"[{name}]");
        }
        void Value(string key, object? value)
        {
            if (value is not null)
                output.WriteLine($"{key}={value.ToString()!.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal)}");
        }

        List<VerificationReport> signatures = result.Signatures.Where(r => r.Title != SignatureVerifier.ContainerTitle).ToList();
        output.WriteLine("; ua-sign verification report");
        Section("summary");
        Value("file", path);
        Value("format", result.Format);
        Value("result", result.IsValid ? "VALID" : "INVALID");
        Value("signatures", signatures.Count);
        Value("warnings", result.Signatures.Sum(r => r.Checks.Count(c => c.Status == CheckStatus.Warning)));
        Value("failures", result.Signatures.Sum(r => r.Checks.Count(c => c.Status == CheckStatus.Failed)));
        Value("verified_at", Time(DateTimeOffset.UtcNow));
        int file = 0;
        foreach (string name in result.SignedFiles.Keys)
            Value($"signed_file.{++file}", name);

        int number = 0;
        foreach (VerificationReport report in result.Signatures)
        {
            string s = report.Title == SignatureVerifier.ContainerTitle ? "container" : $"signature.{++number}";
            Section(s);
            Value("title", report.Title);
            Value("level", report.Level);
            Value("packaging", report.Packaging);
            Value("signature_algorithm", report.SignatureAlgorithm is { } sa ? Algorithm(PkiAlgorithms.SignatureAlgorithmName(sa), sa) : null);
            Value("digest_algorithm", report.DigestAlgorithm is { } da ? Algorithm(PkiAlgorithms.HashName(da), da) : null);
            Value("signing_time", report.ClaimedSigningTime is { } claimed ? Time(claimed) : null);
            Value("timestamp_time", report.TimeStampTime is { } stamped ? Time(stamped) : null);
            if (report.Signer is not null)
                Value("validation_time", Time(report.ValidationTime));
            Value("result", report.IsValid ? report.HasWarnings ? "valid, with warnings" : "valid" : "INVALID");
            Value("warnings", report.Checks.Count(c => c.Status == CheckStatus.Warning));
            Value("failures", report.Checks.Count(c => c.Status == CheckStatus.Failed));

            if (report.Signer is { } signer)
            {
                Section($"{s}.signer");
                Value("subject", signer.Subject);
                Value("issuer", signer.Issuer);
                Value("serial", Serial(signer.SerialNumber));
                Value("valid_from", Time(signer.NotBefore));
                Value("valid_to", Time(signer.NotAfter));
                Value("key", Key(signer));
                Value("certificate_signature_algorithm", Algorithm(PkiAlgorithms.SignatureAlgorithmName(signer.SignatureAlgorithm), signer.SignatureAlgorithm));
            }

            int i = 0;
            foreach (SignedObject signed in report.SignedObjects)
            {
                Section($"{s}.reference.{++i}");
                Value("name", signed.Name);
                Value("digest_algorithm", Algorithm(PkiAlgorithms.HashName(signed.HashAlgorithm), signed.HashAlgorithm));
                Value("digest", Convert.ToHexString(signed.Digest));
            }

            i = 0;
            foreach (TimeStampDetails stamp in report.TimeStamps)
            {
                Section($"{s}.timestamp.{++i}");
                Value("kind", stamp.Kind);
                Value("time", Time(stamp.Token.GenTime));
                Value("serial", Serial(stamp.Token.SerialNumber));
                Value("policy", stamp.Token.Policy);
                Value("imprint_algorithm", Algorithm(PkiAlgorithms.HashName(stamp.Token.ImprintAlgorithm), stamp.Token.ImprintAlgorithm));
                Value("imprint", Convert.ToHexString(stamp.Token.Imprint));
                Value("authority", stamp.Authority?.Subject);
                Value("authority_serial", stamp.Authority is { } tsa ? Serial(tsa.SerialNumber) : null);
            }

            i = 0;
            foreach (CertificatePath chain in report.Paths)
            {
                Section($"{s}.path.{++i}");
                Value("for", chain.Name);
                int j = 0;
                foreach (Certificate c in chain.Certificates)
                {
                    Value($"certificate.{++j}", c.Subject);
                    Value($"certificate.{j}.serial", Serial(c.SerialNumber));
                    Value($"certificate.{j}.valid_from", Time(c.NotBefore));
                    Value($"certificate.{j}.valid_to", Time(c.NotAfter));
                }
            }

            i = 0;
            foreach (RevocationStatus revocation in report.Revocations)
            {
                Section($"{s}.ocsp.{++i}");
                Value("path", revocation.Path);
                Value("certificate", revocation.Certificate.Subject);
                Value("serial", Serial(revocation.Certificate.SerialNumber));
                Value("status", revocation.Status.Status.ToString().ToLowerInvariant());
                Value("revocation_time", revocation.Status.RevocationTime is { } revoked ? Time(revoked) : null);
                Value("source", revocation.Online ? "online" : "embedded");
                Value("responder", revocation.Responder.Subject);
                Value("produced_at", Time(revocation.Response.ProducedAt));
                Value("this_update", Time(revocation.Status.ThisUpdate));
                Value("next_update", revocation.Status.NextUpdate is { } next ? Time(next) : null);
            }

            Section($"{s}.checks");
            i = 0;
            foreach (VerificationCheck check in report.Checks)
            {
                string status = check.Status switch
                {
                    CheckStatus.Passed => "OK",
                    CheckStatus.Warning => "WARN",
                    _ => "FAIL",
                };
                Value((++i).ToString(CultureInfo.InvariantCulture), $"{status} | {check.Name} | {check.Details}");
            }
        }
    }

    public static string Serial(BigInteger serial) => serial.ToString("X", CultureInfo.InvariantCulture).TrimStart('0');

    public static string Key(Certificate c)
    {
        if (!c.HasDstu4145Key)
            return $"key algorithm {c.PublicKeyAlgorithm}";
        var key = c.PublicKey;
        string basis = key.Domain.Field is UA.Cryptography.Math.PolynomialBasisField ? "PB" : "ONB";
        return $"DSTU 4145 key, {basis} m = {key.Domain.Field.M}{(key.Dke is null ? "" : ", with DKE")}";
    }

    private static string Time(DateTimeOffset time) => time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static string Algorithm(string name, string identifier) => name == identifier ? identifier : $"{name} ({identifier})";
}
