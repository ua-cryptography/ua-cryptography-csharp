using System.Numerics;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cms;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Tsp;

/// <summary>
/// An RFC 3161 time-stamp token: CMS SignedData whose content is a DER TSTInfo (docs/signature-formats.md, section 6).
/// The message imprint is the hash of what was time-stamped, not reversed.
/// </summary>
public sealed class TimeStampToken
{
    private TimeStampToken(SignedData cms)
    {
        Cms = cms;
        if (cms.ContentType != Oids.TstInfo || cms.Content is null)
            throw new InvalidDataException("The token does not encapsulate a TSTInfo.");
        if (cms.SignerInfos.Count != 1)
            throw new InvalidDataException("A time-stamp token must have exactly one signer.");

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy OPTIONAL,
        //                        ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }
        Asn1Node info = Asn1Node.Parse(cms.Content).Expect(Asn1Tag.Sequence);
        Policy = info[1].GetOid();
        ImprintAlgorithm = info[2][0][0].GetOid();
        Imprint = info[2][1].GetOctetString();
        SerialNumber = info[3].GetInteger();
        GenTime = info[4].GetTime();
        for (int i = 5; i < info.Count; i++)
        {
            if (info[i].Is(Asn1Tag.Integer))
                Nonce = info[i].GetInteger();
        }
    }

    public static TimeStampToken Load(ReadOnlySpan<byte> data) => new(SignedData.Load(data));

    public SignedData Cms { get; }

    public byte[] Encoded => Cms.Encoded;

    public SignerInfo Signer => Cms.SignerInfos[0];

    public string Policy { get; }

    public string ImprintAlgorithm { get; }

    public byte[] Imprint { get; }

    public BigInteger SerialNumber { get; }

    public DateTimeOffset GenTime { get; }

    public BigInteger? Nonce { get; }

    /// <summary>True when the imprint is the hash of <paramref name="covered"/> by the imprint's algorithm.</summary>
    public bool Covers(ReadOnlySpan<byte> covered) =>
        PkiAlgorithms.IsSupportedHash(ImprintAlgorithm) && Imprint.AsSpan().SequenceEqual(PkiAlgorithms.Hash(ImprintAlgorithm, covered));

    /// <summary>The time-stamping service's certificate: in the token, else among <paramref name="known"/>.</summary>
    public Certificate? FindSignerCertificate(IEnumerable<Certificate>? known = null) => Cms.FindCertificate(Signer, known);

    /// <summary>
    /// Verifies the token over <paramref name="covered"/>: the imprint, the CMS signer and the extended key usage of the
    /// service certificate. Returns the service certificate, or null when it was not found: the token's signature then
    /// stays unverified, which is a warning — the token must not be relied on, but the signature it stamps is not wrong.
    /// </summary>
    public Certificate? Verify(ReadOnlySpan<byte> covered, IEnumerable<Certificate> known, VerificationReport report, string name)
    {
        bool covers = Covers(covered);
        report.Check($"{name}: imprint", covers,
            covers ? $"{PkiAlgorithms.HashName(ImprintAlgorithm)} imprint matches, time {GenTime:yyyy-MM-dd HH:mm:ss} UTC" : "the time-stamp covers other data");

        Certificate? tsa = FindSignerCertificate(known);
        if (tsa is null)
        {
            report.Warn($"{name}: service certificate",
                $"the certificate of the time-stamping service ({Signer}) is not available, so the time-stamp is not verified");
            return null;
        }
        CmsVerifier.VerifySigner(Signer, tsa, Oids.TstInfo, Cms.Content!, report, name);
        if (!tsa.ExtendedKeyUsage.Contains(Oids.KeyPurposeTimeStamping))
            report.Warn($"{name}: service certificate", $"'{tsa.Subject}' has no timeStamping extended key usage");
        return tsa;
    }
}
