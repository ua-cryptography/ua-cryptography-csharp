using System.Security.Cryptography;
using UA.Cryptography.Dstu7564;
using UA.Cryptography.Gost;

namespace UA.Cryptography.Pki;

/// <summary>
/// The algorithms of the Ukrainian PKI by their identifiers: hashes by OID and XML URI, and the signature algorithm
/// that goes with each hash (docs/signature-formats.md, section 2).
/// </summary>
public static class PkiAlgorithms
{
    public const string XmlDstu7564_256 = "http://www.w3.org/2001/04/xmlenc#dstu7564-256";
    public const string XmlGost34311 = "http://www.w3.org/2001/04/xmlenc#gost34311";
    public const string XmlSignatureDstu7564 = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256";
    public const string XmlSignatureGost34311 = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311";
    public const string XmlSha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    public const string XmlSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>
    /// The hash of <paramref name="data"/> by its OID, as the hash function outputs it (no byte reversal). GOST 34.311
    /// uses the S-box table <paramref name="dke"/>, or DKE No. 1 when it is null.
    /// </summary>
    public static byte[] Hash(string oid, ReadOnlySpan<byte> data, byte[]? dke = null)
    {
        switch (oid)
        {
            case Oids.Gost34311:
                if (dke is null)
                    return Gost34311.HashData(data);
                using (Gost34311 gost = Gost34311.FromDke(dke))
                    return gost.ComputeHash(data.ToArray());
            case Oids.Dstu7564_256:
                return Dstu7564Hash.HashData(data, 256);
            case Oids.Dstu7564_384:
                return Dstu7564Hash.HashData(data, 384);
            case Oids.Dstu7564_512:
                return Dstu7564Hash.HashData(data, 512);
            case Oids.Sha1:
                return SHA1.HashData(data);
            case Oids.Sha256:
                return SHA256.HashData(data);
            default:
                throw new NotSupportedException($"Hash algorithm {oid} is not supported.");
        }
    }

    /// <summary>
    /// The hashes a verifier accepts for document data and signed attributes: GOST 34.311 with the signer's DKE and, when
    /// that DKE is not DKE No. 1, also with DKE No. 1 (which table a tool hashes with is not fixed by the formats; current
    /// certificates carry no DKE at all). Other hashes have one value.
    /// </summary>
    public static IEnumerable<byte[]> CandidateHashes(string oid, byte[] data, byte[]? dke)
    {
        yield return Hash(oid, data, dke);
        if (oid == Oids.Gost34311 && dke is not null && !dke.AsSpan().SequenceEqual(Gost34311.DefaultDke))
            yield return Hash(oid, data);
    }

    /// <summary>True when one of the <see cref="CandidateHashes"/> of <paramref name="data"/> equals <paramref name="expected"/>.</summary>
    public static bool DigestMatches(string oid, byte[] data, ReadOnlySpan<byte> expected, byte[]? dke)
    {
        foreach (byte[] hash in CandidateHashes(oid, data, dke))
        {
            if (expected.SequenceEqual(hash))
                return true;
        }
        return false;
    }

    public static bool IsSupportedHash(string oid) =>
        oid is Oids.Gost34311 or Oids.Dstu7564_256 or Oids.Dstu7564_384 or Oids.Dstu7564_512 or Oids.Sha1 or Oids.Sha256;

    /// <summary>The hash a signature algorithm ("DSTU 4145 with …") stands for.</summary>
    public static string HashOfSignatureAlgorithm(string signatureAlgorithm) => signatureAlgorithm switch
    {
        Oids.Dstu4145WithDstu7564 => Oids.Dstu7564_256,
        Oids.Dstu4145WithGost34311 => Oids.Gost34311,
        _ => throw new NotSupportedException($"Signature algorithm {signatureAlgorithm} is not supported."),
    };

    /// <summary>The signature algorithm used with a hash in the national PKI.</summary>
    public static string SignatureAlgorithmFor(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => Oids.Dstu4145WithDstu7564,
        Oids.Gost34311 => Oids.Dstu4145WithGost34311,
        _ => throw new NotSupportedException($"No DSTU 4145 signature algorithm is defined for hash {hashOid}."),
    };

    public static string XmlDigestMethod(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => XmlDstu7564_256,
        Oids.Gost34311 => XmlGost34311,
        _ => throw new NotSupportedException($"No XML digest method for hash {hashOid}."),
    };

    public static string XmlSignatureMethod(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => XmlSignatureDstu7564,
        Oids.Gost34311 => XmlSignatureGost34311,
        _ => throw new NotSupportedException($"No XML signature method for hash {hashOid}."),
    };

    /// <summary>The hash OID behind an XML DigestMethod or SignatureMethod URI.</summary>
    public static string HashOfXmlAlgorithm(string uri) => uri switch
    {
        XmlDstu7564_256 or XmlSignatureDstu7564 => Oids.Dstu7564_256,
        XmlGost34311 or XmlSignatureGost34311 => Oids.Gost34311,
        XmlSha1 => Oids.Sha1,
        XmlSha256 => Oids.Sha256,
        _ => throw new NotSupportedException($"XML algorithm {uri} is not supported."),
    };

    /// <summary>
    /// Parses a hash name as given on a command line or in configuration: "dstu7564" (256 bits), "gost34311", or an OID.
    /// </summary>
    public static string ParseHashName(string name) => name.ToLowerInvariant() switch
    {
        "dstu7564" or "dstu7564-256" or "kupyna" => Oids.Dstu7564_256,
        "gost34311" or "gost" => Oids.Gost34311,
        _ when IsSupportedHash(name) => name,
        _ => throw new ArgumentException($"Unknown hash '{name}' (expected dstu7564 or gost34311).", nameof(name)),
    };

    public static string HashName(string oid) => oid switch
    {
        Oids.Gost34311 => "GOST 34.311-95",
        Oids.Dstu7564_256 => "DSTU 7564-256",
        Oids.Dstu7564_384 => "DSTU 7564-384",
        Oids.Dstu7564_512 => "DSTU 7564-512",
        Oids.Sha1 => "SHA-1",
        Oids.Sha256 => "SHA-256",
        _ => oid,
    };

    /// <summary>The name of a signature algorithm given by its OID or XML-DSig URI; unknown ones are returned as given.</summary>
    public static string SignatureAlgorithmName(string identifier) => identifier switch
    {
        Oids.Dstu4145WithDstu7564 or XmlSignatureDstu7564 => "DSTU 4145 with DSTU 7564-256",
        Oids.Dstu4145WithGost34311 or XmlSignatureGost34311 => "DSTU 4145 with GOST 34.311-95",
        _ => identifier,
    };
}
