using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Validation;

public enum CheckStatus
{
    Passed,

    /// <summary>Something could not be established (no trust anchor, no revocation data); the signature itself holds.</summary>
    Warning,

    Failed,
}

/// <summary>One verification step and its outcome.</summary>
public sealed record VerificationCheck(string Name, CheckStatus Status, string Details);

/// <summary>The outcome of verifying one signature: every check made, the signer and the times found.</summary>
public sealed class VerificationReport(string title)
{
    private readonly List<VerificationCheck> _checks = [];

    /// <summary>What was verified, e.g. "CAdES signature 1" or "XAdES signature-1".</summary>
    public string Title { get; set; } = title;

    /// <summary>The format and level found, e.g. "CAdES-T, enveloped".</summary>
    public string? Format { get; set; }

    public Certificate? Signer { get; set; }

    /// <summary>The signing time claimed by the signer (signingTime, xades:SigningTime).</summary>
    public DateTimeOffset? ClaimedSigningTime { get; set; }

    /// <summary>The time of the signature time-stamp, when present and valid.</summary>
    public DateTimeOffset? TimeStampTime { get; set; }

    /// <summary>The time the certificates are validated at: the time-stamp, else the claimed time, else now.</summary>
    public DateTimeOffset ValidationTime => TimeStampTime ?? ClaimedSigningTime ?? DateTimeOffset.UtcNow;

    public IReadOnlyList<VerificationCheck> Checks => _checks;

    /// <summary>True when no check failed (warnings allowed).</summary>
    public bool IsValid => _checks.Count > 0 && _checks.All(c => c.Status != CheckStatus.Failed);

    public bool HasWarnings => _checks.Any(c => c.Status == CheckStatus.Warning);

    public void Pass(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Passed, details));

    public void Warn(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Warning, details));

    public void Fail(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Failed, details));

    public void Check(string name, bool passed, string details) =>
        _checks.Add(new VerificationCheck(name, passed ? CheckStatus.Passed : CheckStatus.Failed, details));
}
