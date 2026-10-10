using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Validation;

/// <summary>What the verifier may rely on besides the signature itself.</summary>
public sealed class ValidationOptions
{
    /// <summary>Trusted roots (e.g. the ЦЗО certificates). When empty, the chain is built but trust is reported as a warning.</summary>
    public IReadOnlyCollection<Certificate> TrustAnchors { get; init; } = [];

    /// <summary>Certificates that may complete chains (CA certificates kept locally).</summary>
    public IReadOnlyCollection<Certificate> ExtraCertificates { get; init; } = [];

    /// <summary>Asked when the signature carries no revocation data for a certificate; null keeps verification offline.</summary>
    public IOcspService? OnlineOcsp { get; init; }

    /// <summary>Used to download missing CA certificates by authorityInfoAccess; null keeps verification offline.</summary>
    public ICertificateSource? Downloads { get; init; }
}

/// <summary>
/// Builds and checks certification paths (a subset of RFC 5280, section 6): each certificate is signed by the next,
/// is valid at the validation time, CA certificates are CAs, the path ends at a trust anchor, and every certificate
/// below the anchor has a "good" OCSP response from a responder of its issuer.
/// </summary>
public static class CertificatePathValidator
{
    private const int MaxDepth = 10;

    /// <summary>
    /// The path from <paramref name="leaf"/> upwards: each next certificate is one whose subject is the issuer and whose
    /// key verifies the signature. The path stops at a trust anchor, at a self-signed certificate or where no issuer is found.
    /// </summary>
    public static List<Certificate> BuildChain(Certificate leaf, IEnumerable<Certificate> pool, IEnumerable<Certificate> anchors,
        ICertificateSource? downloads = null)
    {
        List<Certificate> candidates = [.. anchors, .. pool];
        var chain = new List<Certificate> { leaf };
        Certificate current = leaf;
        while (chain.Count < MaxDepth)
        {
            if (anchors.Contains(current) || (current.IsSelfIssued && current.IsSignedBy(current)))
                break;
            Certificate? issuer = FindIssuer(current, candidates);
            if (issuer is null && downloads is not null)
            {
                foreach (string url in current.CaIssuerUrls)
                {
                    try
                    {
                        candidates.AddRange(downloads.Download(url));
                    }
                    catch (Exception e) when (e is HttpRequestException or InvalidDataException or TaskCanceledException)
                    {
                        // the issuer stays unknown; reported by the caller
                    }
                }
                issuer = FindIssuer(current, candidates);
            }
            if (issuer is null || chain.Contains(issuer))
                break;
            chain.Add(issuer);
            current = issuer;
        }
        return chain;
    }

    private static Certificate? FindIssuer(Certificate certificate, IEnumerable<Certificate> candidates)
    {
        byte[]? aki = certificate.AuthorityKeyIdentifier;
        return candidates
            .Where(c => !c.Equals(certificate) && c.Subject.Equals(certificate.Issuer))
            .OrderByDescending(c => aki is not null && c.SubjectKeyIdentifier is { } ski && ski.AsSpan().SequenceEqual(aki))
            .FirstOrDefault(certificate.IsSignedBy);
    }

    /// <summary>
    /// Validates the path of <paramref name="leaf"/> at <paramref name="time"/> and adds the checks to <paramref name="report"/>.
    /// <paramref name="revocation"/> is the revocation data carried by the signature.
    /// </summary>
    public static List<Certificate> Validate(Certificate leaf, IEnumerable<Certificate> pool, IReadOnlyCollection<OcspResponse> revocation,
        ValidationOptions options, DateTimeOffset time, VerificationReport report, string name)
    {
        List<Certificate> poolList = [.. pool, .. options.ExtraCertificates];
        List<Certificate> chain = BuildChain(leaf, poolList, options.TrustAnchors, options.Downloads);
        Certificate top = chain[^1];
        report.Add(new CertificatePath(name, chain));
        report.Pass($"{name}: path", string.Join(" → ", chain.Select(c => $"'{Short(c)}'")));

        // Signatures, validity and CA flags along the path.
        for (int i = 0; i < chain.Count; i++)
        {
            Certificate c = chain[i];
            if (i + 1 < chain.Count)
                report.Check($"{name}: signature of '{Short(c)}'", c.IsSignedBy(chain[i + 1]), $"issued by '{Short(chain[i + 1])}'");
            if (!c.IsValidAt(time))
                report.Fail($"{name}: validity of '{Short(c)}'", $"{c.NotBefore:yyyy-MM-dd} – {c.NotAfter:yyyy-MM-dd} does not include {time:yyyy-MM-dd HH:mm} UTC");
            if (i > 0 && !c.IsCa)
                report.Fail($"{name}: '{Short(c)}'", "issues certificates but is not a CA (basicConstraints)");
        }

        // Trust.
        bool selfSigned = top.IsSelfIssued && top.IsSignedBy(top);
        if (options.TrustAnchors.Count > 0)
        {
            bool trusted = options.TrustAnchors.Contains(top);
            report.Check($"{name}: trust", trusted, trusted
                ? $"ends at the trusted '{Short(top)}'"
                : selfSigned ? $"ends at '{Short(top)}', which is not a trusted root" : $"the issuer of '{Short(top)}' is not available");
        }
        else
        {
            report.Warn($"{name}: trust", selfSigned
                ? $"ends at the self-signed '{Short(top)}'; no trusted roots were given"
                : $"incomplete: the issuer of '{Short(top)}' is not available");
        }

        // Revocation of every certificate below the top of the path (the top has no issuer to ask).
        for (int i = 0; i + 1 < chain.Count; i++)
            CheckRevocation(chain[i], chain[i + 1], revocation, poolList, options, time, report, name);
        return chain;
    }

    private static void CheckRevocation(Certificate certificate, Certificate issuer, IReadOnlyCollection<OcspResponse> revocation,
        List<Certificate> pool, ValidationOptions options, DateTimeOffset time, VerificationReport report, string name)
    {
        string check = $"{name}: revocation of '{Short(certificate)}'";
        (OcspResponse Response, OcspSingleResponse Single)? found = revocation
            .Select(r => (Response: r, Single: r.Find(certificate, issuer)))
            .Where(x => x.Single is not null)
            .Select(x => ((OcspResponse, OcspSingleResponse)?)(x.Response, x.Single!))
            .FirstOrDefault();
        string source = "embedded";
        if (found is null && options.OnlineOcsp is not null)
        {
            try
            {
                OcspResponse? online = options.OnlineOcsp.GetResponse(certificate, issuer, Oids.Dstu7564_256);
                if (online?.Find(certificate, issuer) is { } single)
                {
                    found = (online, single);
                    source = "online";
                    time = DateTimeOffset.UtcNow;
                }
            }
            catch (Exception e) when (e is HttpRequestException or InvalidDataException or TaskCanceledException)
            {
                report.Warn(check, $"the OCSP request failed: {e.Message}");
                return;
            }
        }
        if (found is null)
        {
            report.Warn(check, "no OCSP response (the signature has no revocation data)");
            return;
        }

        var (response, status) = found.Value;
        Certificate? responder = response.FindResponder([.. pool, issuer]);
        if (responder is null)
        {
            report.Fail(check, "the OCSP responder's certificate is not available");
            return;
        }
        if (!response.IsSignedBy(responder))
        {
            report.Fail(check, $"the OCSP response is not signed by '{Short(responder)}'");
            return;
        }
        bool authorized = responder.Equals(issuer)
            || (responder.IsSignedBy(issuer) && responder.ExtendedKeyUsage.Contains(Oids.KeyPurposeOcspSigning));
        if (!authorized)
        {
            report.Fail(check, $"'{Short(responder)}' is not an OCSP responder of '{Short(issuer)}'");
            return;
        }

        report.Add(new RevocationStatus(name, certificate, response, status, responder, source == "online"));
        string at = $"{source} response of '{Short(responder)}' at {status.ThisUpdate:yyyy-MM-dd HH:mm} UTC";
        switch (status.Status)
        {
            case OcspCertificateStatus.Good:
                report.Pass(check, $"good, {at}");
                break;
            case OcspCertificateStatus.Revoked when status.RevocationTime > time:
                report.Pass(check, $"revoked on {status.RevocationTime:yyyy-MM-dd HH:mm} UTC, after the validation time; {at}");
                break;
            case OcspCertificateStatus.Revoked:
                report.Fail(check, $"revoked on {status.RevocationTime:yyyy-MM-dd HH:mm} UTC; {at}");
                break;
            default:
                report.Fail(check, $"unknown to the responder; {at}");
                break;
        }
    }

    public static string Short(Certificate c) => c.Subject.Get(Oids.CommonName) ?? c.Subject.ToString();
}
