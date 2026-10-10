namespace UA.Cryptography.Pki;

/// <summary>Object identifiers used by the Ukrainian PKI and by the formats of this package (docs/signature-formats.md, section 2).</summary>
public static class Oids
{
    // ---- Ukrainian algorithms (arc 1.2.804.2.1.1.1) ------------------------------------------------------------

    /// <summary>GOST 34.311-95 hash.</summary>
    public const string Gost34311 = "1.2.804.2.1.1.1.1.2.1";

    /// <summary>DSTU 7564:2014 hash, 256 bits.</summary>
    public const string Dstu7564_256 = "1.2.804.2.1.1.1.1.2.2.1";

    /// <summary>DSTU 7564:2014 hash, 384 bits.</summary>
    public const string Dstu7564_384 = "1.2.804.2.1.1.1.1.2.2.2";

    /// <summary>DSTU 7564:2014 hash, 512 bits.</summary>
    public const string Dstu7564_512 = "1.2.804.2.1.1.1.1.2.2.3";

    /// <summary>
    /// DSTU 4145 key whose octet strings (B, base point, public key, private key) are little-endian; the same OID
    /// names the signature algorithm "DSTU 4145 with GOST 34.311".
    /// </summary>
    public const string Dstu4145Le = "1.2.804.2.1.1.1.1.3.1.1";

    /// <summary>DSTU 4145 key whose octet strings are big-endian.</summary>
    public const string Dstu4145Be = "1.2.804.2.1.1.1.1.3.1.1.1.1";

    /// <summary>Signature algorithm DSTU 4145 with GOST 34.311.</summary>
    public const string Dstu4145WithGost34311 = Dstu4145Le;

    /// <summary>Signature algorithm DSTU 4145 with DSTU 7564-256.</summary>
    public const string Dstu4145WithDstu7564 = "1.2.804.2.1.1.1.1.3.6.1.1";

    /// <summary>Named curves: the i-th curve of table Г.1 of DSTU 4145-2002 is this prefix followed by i.</summary>
    public const string NamedCurvePrefix = "1.2.804.2.1.1.1.1.3.1.1.2.";

    /// <summary>Time-stamping policy used with GOST 34.311.</summary>
    public const string TspPolicyGost34311 = "1.2.804.2.1.1.1.2.3.1";

    /// <summary>Time-stamping policy used with DSTU 7564.</summary>
    public const string TspPolicyDstu7564 = "1.2.804.2.1.1.1.2.3.4.1.1";

    // ---- International hashes (ESS certificate identifiers default to them) -------------------------------------

    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";

    // ---- X.500 attribute types -------------------------------------------------------------------------------

    public const string CommonName = "2.5.4.3";
    public const string Surname = "2.5.4.4";
    public const string SerialNumber = "2.5.4.5";
    public const string Country = "2.5.4.6";
    public const string Locality = "2.5.4.7";
    public const string State = "2.5.4.8";
    public const string Street = "2.5.4.9";
    public const string Organization = "2.5.4.10";
    public const string OrganizationalUnit = "2.5.4.11";
    public const string Title = "2.5.4.12";
    public const string GivenName = "2.5.4.42";
    public const string OrganizationIdentifier = "2.5.4.97";
    public const string EmailAddress = "1.2.840.113549.1.9.1";

    // ---- X.509 extensions (RFC 5280) -------------------------------------------------------------------------

    public const string SubjectKeyIdentifier = "2.5.29.14";
    public const string KeyUsage = "2.5.29.15";
    public const string BasicConstraints = "2.5.29.19";
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    public const string ExtendedKeyUsage = "2.5.29.37";
    public const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    public const string SubjectInfoAccess = "1.3.6.1.5.5.7.1.11";
    public const string AccessOcsp = "1.3.6.1.5.5.7.48.1";
    public const string AccessCaIssuers = "1.3.6.1.5.5.7.48.2";
    public const string AccessTimeStamping = "1.3.6.1.5.5.7.48.3";
    public const string KeyPurposeTimeStamping = "1.3.6.1.5.5.7.3.8";
    public const string KeyPurposeOcspSigning = "1.3.6.1.5.5.7.3.9";

    // ---- CMS (RFC 5652) and its attributes -------------------------------------------------------------------

    public const string Data = "1.2.840.113549.1.7.1";
    public const string SignedData = "1.2.840.113549.1.7.2";
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    public const string ContentType = "1.2.840.113549.1.9.3";
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    public const string SigningTime = "1.2.840.113549.1.9.5";
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    public const string SignatureTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    public const string ContentTimeStamp = "1.2.840.113549.1.9.16.2.20";
    public const string CertificateRefs = "1.2.840.113549.1.9.16.2.21";
    public const string RevocationRefs = "1.2.840.113549.1.9.16.2.22";
    public const string CertValues = "1.2.840.113549.1.9.16.2.23";
    public const string RevocationValues = "1.2.840.113549.1.9.16.2.24";

    // ---- OCSP (RFC 6960) -------------------------------------------------------------------------------------

    public const string OcspBasic = "1.3.6.1.5.5.7.48.1.1";
    public const string OcspNonce = "1.3.6.1.5.5.7.48.1.2";

    // ---- Key stores ------------------------------------------------------------------------------------------

    /// <summary>The Sun JKS key protector.</summary>
    public const string JksKeyProtector = "1.3.6.1.4.1.42.2.17.1.1";
}
