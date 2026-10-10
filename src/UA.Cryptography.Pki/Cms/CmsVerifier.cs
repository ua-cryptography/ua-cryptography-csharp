using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Cms;

/// <summary>
/// The checks of one CMS signer (docs/signature-formats.md, sections 6 and 9): contentType and messageDigest bind the
/// signed attributes to the content, signingCertificate(V2) binds them to the certificate, and the DSTU 4145 signature
/// covers their DER encoding.
/// </summary>
public static class CmsVerifier
{
    /// <summary>Adds the checks of <paramref name="signer"/> to <paramref name="report"/> under the given name prefix.</summary>
    public static void VerifySigner(SignerInfo signer, Certificate certificate, string contentType, byte[] content, VerificationReport report, string prefix)
    {
        byte[]? dke = certificate.HasDstu4145Key ? certificate.PublicKey.Dke : null;
        if (signer.SignedAttributesForSignature is null)
        {
            report.Fail($"{prefix}: signed attributes", "the signer has no signed attributes");
            return;
        }

        CmsAttribute? type = signer.FindSigned(Oids.ContentType);
        if (type is null || type.Value.GetOid() != contentType)
            report.Fail($"{prefix}: contentType", type is null ? "the attribute is missing" : $"{type.Value.GetOid()} instead of {contentType}");

        CmsAttribute? digest = signer.FindSigned(Oids.MessageDigest);
        if (digest is null)
        {
            report.Fail($"{prefix}: messageDigest", "the attribute is missing");
        }
        else if (!PkiAlgorithms.IsSupportedHash(signer.DigestAlgorithm))
        {
            report.Fail($"{prefix}: messageDigest", $"hash algorithm {signer.DigestAlgorithm} is not supported");
            return;
        }
        else
        {
            bool matches = PkiAlgorithms.DigestMatches(signer.DigestAlgorithm, content, digest.Value.GetOctetString(), dke);
            report.Check($"{prefix}: messageDigest", matches,
                matches ? $"{PkiAlgorithms.HashName(signer.DigestAlgorithm)} of the content matches" : "the content does not match the signed hash");
        }

        CheckSigningCertificate(signer, certificate, report, prefix);

        bool valid;
        try
        {
            valid = certificate.PublicKey.VerifyData(signer.DigestAlgorithm, signer.SignedAttributesForSignature, signer.Signature);
        }
        catch (Exception e) when (e is NotSupportedException or InvalidDataException or ArgumentException)
        {
            report.Fail($"{prefix}: signature", e.Message);
            return;
        }
        report.Check($"{prefix}: signature", valid, valid ? $"DSTU 4145 signature of {certificate.Subject.Get(Oids.CommonName) ?? certificate.Subject.ToString()}" : "the DSTU 4145 signature does not verify");
    }

    /// <summary>signingCertificateV2 (or the SHA-1 signingCertificate) names exactly this certificate.</summary>
    public static void CheckSigningCertificate(SignerInfo signer, Certificate certificate, VerificationReport report, string prefix)
    {
        CmsAttribute? v2 = signer.FindSigned(Oids.SigningCertificateV2);
        CmsAttribute? v1 = signer.FindSigned(Oids.SigningCertificate);
        if (v2 is null && v1 is null)
        {
            report.Warn($"{prefix}: signing certificate", "neither signingCertificateV2 nor signingCertificate is present");
            return;
        }

        // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
        // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial OPTIONAL }
        Asn1Node first = (v2 ?? v1)!.Value[0][0];
        string hashOid = v2 is null ? Oids.Sha1 : first[0].Is(Asn1Tag.Sequence) ? first[0][0].GetOid() : Oids.Sha256;
        byte[] hash = (first[0].Is(Asn1Tag.Sequence) ? first[1] : first[0]).GetOctetString();
        byte[]? dke = certificate.HasDstu4145Key ? certificate.PublicKey.Dke : null;
        bool matches = PkiAlgorithms.IsSupportedHash(hashOid) && PkiAlgorithms.DigestMatches(hashOid, certificate.Encoded, hash, dke);
        report.Check($"{prefix}: signing certificate", matches,
            matches ? $"{PkiAlgorithms.HashName(hashOid)} of the certificate matches" : "the signed attributes name a different certificate");
    }
}
