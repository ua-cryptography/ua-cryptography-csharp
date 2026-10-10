using UA.Cryptography.Pki.Validation;

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
}
