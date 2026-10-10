using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki;

/// <summary>Signature levels common to CAdES and XAdES.</summary>
public enum SignatureLevel
{
    /// <summary>Basic: the signed attributes / signed properties only.</summary>
    B,

    /// <summary>+ a time-stamp over the signature value.</summary>
    T,

    /// <summary>
    /// + the certificates and OCSP responses needed for long-term validation: XAdES-B-LT, and CAdES-X Long (with the
    /// complete certificate and revocation references, as Ukrainian qualified tools write it).
    /// </summary>
    LT,
}

/// <summary>The online services a signer uses for levels T and LT.</summary>
public sealed class SignatureServices
{
    /// <summary>The time-stamping service (required for T and LT).</summary>
    public ITimeStampService? TimeStamps { get; init; }

    /// <summary>The OCSP service (required for LT).</summary>
    public IOcspService? Ocsp { get; init; }

    /// <summary>Downloads missing CA certificates (optional).</summary>
    public ICertificateSource? Downloads { get; init; }

    /// <summary>CA certificates kept locally that complete the signer's chain.</summary>
    public IReadOnlyCollection<Certificate> ExtraCertificates { get; init; } = [];

    internal ITimeStampService RequireTimeStamps() =>
        TimeStamps ?? throw new InvalidOperationException("Levels T and LT need a time-stamping service.");

    internal LongTermValidationData CollectLongTermData(SigningKey signer, string hashOid) =>
        LongTermValidationData.Collect(signer, ExtraCertificates,
            Ocsp ?? throw new InvalidOperationException("Level LT needs an OCSP service."), Downloads, hashOid);
}
