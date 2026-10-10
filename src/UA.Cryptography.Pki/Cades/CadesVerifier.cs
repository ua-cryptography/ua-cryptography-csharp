using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cms;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Cades;

/// <summary>
/// Verifies CAdES signatures (docs/signature-formats.md, section 9): for every signer the binding to the data and to
/// the certificate, the DSTU 4145 signature, the time-stamps, the long-term validation values and the certificate path.
/// </summary>
public static class CadesVerifier
{
    /// <summary>Verifies a .p7s; <paramref name="detachedContent"/> is the data of a detached signature.</summary>
    public static VerificationResult Verify(byte[] signature, byte[]? detachedContent, ValidationOptions options)
    {
        SignedData cms = SignedData.Load(signature);
        byte[]? content = cms.Content ?? detachedContent;
        var reports = new List<VerificationReport>();
        for (int i = 0; i < cms.SignerInfos.Count; i++)
            reports.Add(VerifySigner(cms, cms.SignerInfos[i], content, options, cms.SignerInfos.Count == 1 ? "CAdES signature" : $"CAdES signature {i + 1}"));
        var files = new Dictionary<string, byte[]>();
        if (content is not null)
            files["content"] = content;
        return new VerificationResult(cms.Content is null ? "CAdES (detached)" : "CAdES (enveloped)", reports) { SignedFiles = files };
    }

    private static VerificationReport VerifySigner(SignedData cms, SignerInfo signer, byte[]? content, ValidationOptions options, string title)
    {
        var report = new VerificationReport(title);

        List<Certificate> certValues = signer.FindUnsigned(Oids.CertValues) is { } cv
            ? cv.Value.Children.Select(c => Certificate.Load(c.Encoded.Span)).ToList()
            : [];
        List<OcspResponse> ocspValues = ReadRevocationValues(signer);
        List<Certificate> known = [.. cms.Certificates, .. certValues, .. options.ExtraCertificates];

        Certificate? certificate = cms.FindCertificate(signer, known);
        bool hasTimeStamp = signer.FindUnsigned(Oids.SignatureTimeStampToken) is not null;
        bool longTerm = certValues.Count > 0 || ocspValues.Count > 0;
        report.Format = $"CAdES-{(longTerm ? "X Long" : hasTimeStamp ? "T" : "B")}, {(cms.Content is null ? "detached" : "enveloped")}, "
            + PkiAlgorithms.HashName(signer.DigestAlgorithm);
        if (certificate is null)
        {
            report.Fail("signer certificate", $"the certificate ({signer}) is not in the signature and was not given");
            return report;
        }
        report.Signer = certificate;
        if (content is null)
        {
            report.Fail("content", "the signature is detached and the signed data was not given");
            return report;
        }

        CmsVerifier.VerifySigner(signer, certificate, cms.ContentType, content, report, "CMS");

        if (signer.FindSigned(Oids.SigningTime) is { } time)
            report.ClaimedSigningTime = time.Value.GetTime();

        // Time-stamps: contentTimeStamp over the data, signatureTimeStampToken over the signature value.
        List<Certificate> tsaPool = [.. known];
        if (signer.FindSigned(Oids.ContentTimeStamp) is { } contentStamp)
            VerifyTimeStamp(contentStamp.Value, content, tsaPool, options, report, "content time-stamp");
        if (signer.FindUnsigned(Oids.SignatureTimeStampToken) is { } signatureStamp)
        {
            TimeStampToken? token = VerifyTimeStamp(signatureStamp.Value, signer.Signature, tsaPool, options, report, "signature time-stamp");
            if (token is not null && report.Checks.Where(c => c.Name.StartsWith("signature time-stamp", StringComparison.Ordinal)).All(c => c.Status != CheckStatus.Failed))
                report.TimeStampTime = token.GenTime;
        }

        if (signer.FindUnsigned(Oids.CertificateRefs) is not null || signer.FindUnsigned(Oids.RevocationRefs) is not null)
            CheckReferences(signer, certValues, ocspValues, report);

        CertificatePathValidator.Validate(certificate, [.. known, .. tsaPool], ocspValues, options, report.ValidationTime, report, "signer");
        return report;
    }

    private static TimeStampToken? VerifyTimeStamp(Asn1Node value, byte[] covered, List<Certificate> pool, ValidationOptions options,
        VerificationReport report, string name)
    {
        TimeStampToken token;
        try
        {
            token = TimeStampToken.Load(value.Encoded.Span);
        }
        catch (InvalidDataException e)
        {
            report.Fail(name, e.Message);
            return null;
        }
        Certificate? tsa = token.Verify(covered, pool, report, name);
        if (tsa is not null)
        {
            pool.AddRange(token.Cms.Certificates);
            CertificatePathValidator.Validate(tsa, pool, [], options, token.GenTime, report, $"{name} service");
        }
        return token;
    }

    // RevocationValues ::= SEQUENCE { crlVals [0] OPTIONAL, ocspVals [1] EXPLICIT SEQUENCE OF BasicOCSPResponse OPTIONAL, ... }
    private static List<OcspResponse> ReadRevocationValues(SignerInfo signer)
    {
        if (signer.FindUnsigned(Oids.RevocationValues) is not { } values)
            return [];
        Asn1Node? ocsp = values.Value.Children.FirstOrDefault(c => c.IsContext(1));
        return ocsp is null ? [] : ocsp[0].Children.Select(r => OcspResponse.LoadBasic(r.Encoded.Span)).ToList();
    }

    /// <summary>Every complete certificate / revocation reference has a value with the same hash (CAdES-C ↔ CAdES-X Long).</summary>
    private static void CheckReferences(SignerInfo signer, List<Certificate> certValues, List<OcspResponse> ocspValues, VerificationReport report)
    {
        if (signer.FindUnsigned(Oids.CertificateRefs) is { } certRefs)
        {
            int missing = certRefs.Value.Children.Count(r => !certValues.Any(c => HashMatches(r[0], c.Encoded)));
            report.Check("certificate references", missing == 0,
                missing == 0 ? $"{certRefs.Value.Count} references match certValues" : $"{missing} references have no matching certificate");
        }
        if (signer.FindUnsigned(Oids.RevocationRefs) is { } revRefs)
        {
            // CrlOcspRef ::= SEQUENCE { crlids [0], ocspids [1] EXPLICIT OcspListID, otherRev [2] }
            // OcspListID ::= SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID { ocspIdentifier, ocspRepHash OPTIONAL } }
            List<Asn1Node> ids = revRefs.Value.Children
                .SelectMany(r => r.Children.Where(c => c.IsContext(1)))
                .SelectMany(o => o[0][0].Children)
                .ToList();
            int missing = ids.Count(id => id.Count > 1 && !ocspValues.Any(r => HashMatches(id[1], r.BasicEncoded)));
            report.Check("revocation references", missing == 0,
                missing == 0 ? $"{ids.Count} OCSP references match revocationValues" : $"{missing} OCSP references have no matching response");
        }
    }

    // OtherHash ::= CHOICE { sha1Hash OCTET STRING, otherHash SEQUENCE { hashAlgorithm, hashValue } }
    private static bool HashMatches(Asn1Node otherHash, byte[] encoded)
    {
        (string oid, byte[] value) = otherHash.Is(Asn1Tag.OctetString)
            ? (Oids.Sha1, otherHash.GetOctetString())
            : (otherHash[0][0].GetOid(), otherHash[1].GetOctetString());
        return PkiAlgorithms.IsSupportedHash(oid) && value.AsSpan().SequenceEqual(PkiAlgorithms.Hash(oid, encoded));
    }
}
