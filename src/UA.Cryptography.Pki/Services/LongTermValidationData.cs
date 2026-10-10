using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Services;

/// <summary>
/// What a long-term signature (CAdES-X Long, XAdES-B-LT) carries so that it can be validated later without the
/// network: the certificates of the signer's chain and of the services, and "good" OCSP responses for every certificate
/// below the root.
/// </summary>
public sealed class LongTermValidationData
{
    private LongTermValidationData(IReadOnlyList<Certificate> chain, IReadOnlyList<OcspResponse> responses, IReadOnlyList<Certificate> certificates)
    {
        Chain = chain;
        Responses = responses;
        Certificates = certificates;
    }

    /// <summary>The signer's path: signer, CAs, root.</summary>
    public IReadOnlyList<Certificate> Chain { get; }

    /// <summary>The CA certificates above the signer, followed by the OCSP responder certificates.</summary>
    public IReadOnlyList<Certificate> Certificates { get; }

    /// <summary>One "good" response per certificate below the root, signer first.</summary>
    public IReadOnlyList<OcspResponse> Responses { get; }

    /// <summary>
    /// Builds the signer's path (downloading missing CA certificates when <paramref name="downloads"/> is given) and
    /// asks <paramref name="ocsp"/> about every certificate below the root. Throws when the path is incomplete or a
    /// response is missing, unsigned or not "good".
    /// </summary>
    public static LongTermValidationData Collect(SigningKey signer, IEnumerable<Certificate> extra, IOcspService ocsp,
        ICertificateSource? downloads, string hashOid)
    {
        List<Certificate> chain = CertificatePathValidator.BuildChain(signer.Certificate, [.. signer.Chain, .. extra], [], downloads);
        Certificate top = chain[^1];
        if (!(top.IsSelfIssued && top.IsSignedBy(top)))
        {
            throw new InvalidOperationException(
                $"The certificate path ends at '{CertificatePathValidator.Short(top)}' whose issuer is not available; add the CA certificates.");
        }

        var responses = new List<OcspResponse>();
        var certificates = new List<Certificate>(chain.Skip(1));
        for (int i = 0; i + 1 < chain.Count; i++)
        {
            Certificate certificate = chain[i];
            Certificate issuer = chain[i + 1];
            string subject = CertificatePathValidator.Short(certificate);
            OcspResponse response = ocsp.GetResponse(certificate, issuer, hashOid)
                ?? throw new InvalidOperationException($"No OCSP responder is known for '{subject}'.");
            OcspSingleResponse single = response.Find(certificate, issuer)
                ?? throw new InvalidDataException($"The OCSP response does not cover '{subject}'.");
            Certificate responder = response.FindResponder([.. certificates, .. chain])
                ?? throw new InvalidDataException($"The OCSP responder's certificate for '{subject}' is not available.");
            if (!response.IsSignedBy(responder))
                throw new InvalidDataException($"The OCSP response for '{subject}' is not signed by its responder.");
            if (single.Status != OcspCertificateStatus.Good)
                throw new InvalidOperationException($"The certificate '{subject}' is {single.Status.ToString().ToLowerInvariant()} according to OCSP.");
            responses.Add(response);
            if (!certificates.Contains(responder) && !responder.Equals(signer.Certificate))
                certificates.Add(responder);
        }
        return new LongTermValidationData(chain, responses, certificates);
    }
}
