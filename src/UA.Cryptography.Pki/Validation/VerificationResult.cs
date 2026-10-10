namespace UA.Cryptography.Pki.Validation;

/// <summary>The outcome of verifying a signed file: one report per signature and the signed content.</summary>
public sealed class VerificationResult(string format, IReadOnlyList<VerificationReport> signatures)
{
    /// <summary>The container found, e.g. "CAdES (.p7s)" or "ASiC-E".</summary>
    public string Format { get; } = format;

    public IReadOnlyList<VerificationReport> Signatures { get; } = signatures;

    /// <summary>The signed files by name (the encapsulated content of a CAdES signature is named "content").</summary>
    public IReadOnlyDictionary<string, byte[]> SignedFiles { get; init; } = new Dictionary<string, byte[]>();

    /// <summary>True when there is at least one signature and none has a failed check.</summary>
    public bool IsValid => Signatures.Count > 0 && Signatures.All(s => s.IsValid);
}
