using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Tsp;
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

/// <summary>What a signature covers: a reference (XAdES) or the content (CAdES), with the digest the signature holds.</summary>
public sealed record SignedObject(string Name, string HashAlgorithm, byte[] Digest);

/// <summary>A time-stamp found on the signature: its kind (e.g. "signature time-stamp"), the token and the service's certificate.</summary>
public sealed record TimeStampDetails(string Kind, TimeStampToken Token, Certificate? Authority);

/// <summary>A certification path built for <see cref="Name"/> (e.g. "signer"), from the certificate up to the top.</summary>
public sealed record CertificatePath(string Name, IReadOnlyList<Certificate> Certificates);

/// <summary>The status of a certificate on a path, established from an authorized OCSP response.</summary>
public sealed record RevocationStatus(string Path, Certificate Certificate, OcspResponse Response, OcspSingleResponse Status,
    Certificate Responder, bool Online);

/// <summary>
/// The outcome of verifying one signature: every check made, the signer and the times found, and what the checks were
/// made on — algorithms, signed objects, time-stamps, certification paths and revocation statuses.
/// </summary>
public sealed class VerificationReport(string title)
{
    private readonly List<VerificationCheck> _checks = [];
    private readonly List<SignedObject> _signedObjects = [];
    private readonly List<TimeStampDetails> _timeStamps = [];
    private readonly List<CertificatePath> _paths = [];
    private readonly List<RevocationStatus> _revocations = [];

    /// <summary>What was verified, e.g. "CAdES signature 1" or "XAdES signature-1".</summary>
    public string Title { get; set; } = title;

    /// <summary>The format and level found, e.g. "CAdES-T, enveloped".</summary>
    public string? Format { get; set; }

    /// <summary>The format and level alone, e.g. "XAdES-B-LT" or "CAdES-T".</summary>
    public string? Level { get; set; }

    /// <summary>"detached" or "enveloped".</summary>
    public string? Packaging { get; set; }

    /// <summary>The signature algorithm as the signature names it: an OID in CMS, a URI in XML-DSig.</summary>
    public string? SignatureAlgorithm { get; set; }

    /// <summary>The OID of the hash the signature is computed over.</summary>
    public string? DigestAlgorithm { get; set; }

    public Certificate? Signer { get; set; }

    /// <summary>The signing time claimed by the signer (signingTime, xades:SigningTime).</summary>
    public DateTimeOffset? ClaimedSigningTime { get; set; }

    /// <summary>The time of the signature time-stamp, when present and valid.</summary>
    public DateTimeOffset? TimeStampTime { get; set; }

    /// <summary>The time the certificates are validated at: the time-stamp, else the claimed time, else now.</summary>
    public DateTimeOffset ValidationTime => TimeStampTime ?? ClaimedSigningTime ?? DateTimeOffset.UtcNow;

    public IReadOnlyList<VerificationCheck> Checks => _checks;

    public IReadOnlyList<SignedObject> SignedObjects => _signedObjects;

    public IReadOnlyList<TimeStampDetails> TimeStamps => _timeStamps;

    public IReadOnlyList<CertificatePath> Paths => _paths;

    public IReadOnlyList<RevocationStatus> Revocations => _revocations;

    /// <summary>True when no check failed (warnings allowed).</summary>
    public bool IsValid => _checks.Count > 0 && _checks.All(c => c.Status != CheckStatus.Failed);

    public bool HasWarnings => _checks.Any(c => c.Status == CheckStatus.Warning);

    public void Pass(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Passed, details));

    public void Warn(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Warning, details));

    public void Fail(string name, string details) => _checks.Add(new VerificationCheck(name, CheckStatus.Failed, details));

    public void Check(string name, bool passed, string details) =>
        _checks.Add(new VerificationCheck(name, passed ? CheckStatus.Passed : CheckStatus.Failed, details));

    public void Add(SignedObject signedObject) => _signedObjects.Add(signedObject);

    public void Add(TimeStampDetails timeStamp) => _timeStamps.Add(timeStamp);

    public void Add(CertificatePath path) => _paths.Add(path);

    public void Add(RevocationStatus revocation) => _revocations.Add(revocation);
}
