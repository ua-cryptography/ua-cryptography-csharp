using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Gost;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.X509;

/// <summary>
/// A DSTU 4145 private key with its domain parameters and DKE. Signs raw hashes by the national convention
/// (docs/signature-formats.md, section 1): the hash is reversed before 5.9 and D = S‖R is returned little-endian.
/// </summary>
/// <remarks>
/// d is a <see cref="BigInteger"/> and cannot be wiped from memory; the byte buffers this class creates are wiped.
/// </remarks>
public sealed class Dstu4145PrivateKey
{
    public Dstu4145PrivateKey(Dstu4145DomainParameters domain, BigInteger d, byte[]? dke = null, bool littleEndian = true)
    {
        Domain = domain;
        D = d;
        Dke = dke;
        LittleEndian = littleEndian;
        PublicKey = new Dstu4145PublicKey(domain, new Dstu4145Signer(domain).ComputePublicKey(d), dke, littleEndian);
    }

    public Dstu4145DomainParameters Domain { get; }

    public BigInteger D { get; }

    public byte[]? Dke { get; }

    public bool LittleEndian { get; }

    /// <summary>Q = −dP (clause 9) with the same parameters and DKE.</summary>
    public Dstu4145PublicKey PublicKey { get; }

    /// <summary>A fresh key on <paramref name="domain"/> (clause 9), with DKE No. 1 written explicitly.</summary>
    public static Dstu4145PrivateKey Generate(Dstu4145DomainParameters domain, RandomNumberGenerator? rng = null)
    {
        Dstu4145KeyPair pair = new Dstu4145Signer(domain, rng).GenerateKeyPair();
        return new Dstu4145PrivateKey(domain, pair.PrivateKey, Gost34311.DefaultDke.ToArray());
    }

    /// <summary>Signs a raw hash (as the hash function outputs it) and returns D little-endian.</summary>
    public byte[] SignHash(ReadOnlySpan<byte> rawHash, RandomNumberGenerator? rng = null)
    {
        byte[] d = new Dstu4145Signer(Domain, rng).SignHash(D, Dstu4145PublicKey.Reversed(rawHash));
        Array.Reverse(d);
        return d;
    }

    /// <summary>Hashes <paramref name="data"/> with the hash of <paramref name="signatureAlgorithm"/> (GOST 34.311 with this key's DKE) and signs.</summary>
    public byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data) =>
        SignHash(PkiAlgorithms.Hash(PkiAlgorithms.HashOfSignatureAlgorithm(signatureAlgorithm), data, Dke));

    // ---- PKCS#8 PrivateKeyInfo (RFC 5208) -----------------------------------------------------------------------

    /// <summary>
    /// PrivateKeyInfo as stored in JKS by Ukrainian banks: version 0, the key AlgorithmIdentifier and d as an
    /// OCTET STRING of ⌈L(n)/8⌉ bytes in the byte order of the key OID (little-endian for <see cref="Oids.Dstu4145Le"/>).
    /// </summary>
    public byte[] ToPkcs8()
    {
        byte[] d = Dstu4145PublicKey.ToFixed(D, ScalarLength(Domain), LittleEndian);
        try
        {
            return Der.Sequence(Der.Integer(0), Dstu4145PublicKey.EncodeAlgorithm(Domain, Dke, LittleEndian), Der.OctetString(d));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(d);
        }
    }

    /// <summary>
    /// Parses PrivateKeyInfo. Besides the raw octet string of d, the BouncyCastle form (an OCTET STRING holding a DER
    /// INTEGER, big-endian) is accepted; the two are told apart by their length.
    /// </summary>
    public static Dstu4145PrivateKey FromPkcs8(ReadOnlyMemory<byte> pkcs8)
    {
        Asn1Node info = Asn1Node.Parse(pkcs8).Expect(Asn1Tag.Sequence);
        var (domain, dke, littleEndian) = Dstu4145PublicKey.ParseAlgorithm(info[1]);
        byte[] raw = info[2].Expect(Asn1Tag.OctetString).GetOctetString();
        try
        {
            BigInteger d;
            if (raw.Length != ScalarLength(domain) && Asn1Node.TryParse(raw, out Asn1Node? integer) && integer!.Is(Asn1Tag.Integer))
                d = integer.GetInteger();
            else
                d = new BigInteger(raw, isUnsigned: true, isBigEndian: !littleEndian);
            if (d.Sign <= 0 || d >= domain.N)
                throw new InvalidDataException("The DSTU 4145 private key is out of range (0, n).");
            return new Dstu4145PrivateKey(domain, d, dke, littleEndian);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static int ScalarLength(Dstu4145DomainParameters domain) => (int)((domain.N.GetBitLength() + 7) / 8);
}
