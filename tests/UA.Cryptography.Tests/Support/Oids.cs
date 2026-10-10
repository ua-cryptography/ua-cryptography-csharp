namespace UA.Cryptography.Tests.Support;

/// <summary>Object identifiers of the Ukrainian PKI (arc 1.2.804.2.1.1.1) used by the tests.</summary>
internal static class Oids
{
    /// <summary>
    /// DSTU 4145 key whose octet strings (B, base point, public key) are little-endian; the same OID names the
    /// signature algorithm "DSTU 4145 with GOST 34.311".
    /// </summary>
    public const string Dstu4145Le = "1.2.804.2.1.1.1.1.3.1.1";

    /// <summary>Signature algorithm: DSTU 4145 with GOST 34.311.</summary>
    public const string Dstu4145WithGost34311 = Dstu4145Le;

    /// <summary>Signature algorithm: DSTU 4145 with DSTU 7564-256.</summary>
    public const string Dstu4145WithDstu7564 = "1.2.804.2.1.1.1.1.3.6.1.1";

    /// <summary>Named curves: the i-th curve of table Г.1 is this prefix followed by i.</summary>
    public const string NamedCurvePrefix = "1.2.804.2.1.1.1.1.3.1.1.2.";

    /// <summary>Hash algorithm GOST 34.311-95.</summary>
    public const string Gost34311 = "1.2.804.2.1.1.1.1.2.1";

    /// <summary>Hash algorithm DSTU 7564:2014, 256 bits.</summary>
    public const string Dstu7564_256 = "1.2.804.2.1.1.1.1.2.2.1";

    /// <summary>Time-stamping policy used with GOST 34.311.</summary>
    public const string TspPolicyGost34311 = "1.2.804.2.1.1.1.2.3.1";

    /// <summary>Time-stamping policy used with DSTU 7564.</summary>
    public const string TspPolicyDstu7564 = "1.2.804.2.1.1.1.2.3.4.1.1";
}
