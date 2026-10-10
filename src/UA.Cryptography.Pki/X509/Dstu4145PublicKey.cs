using System.Collections.Concurrent;
using System.Numerics;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Math;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.X509;

/// <summary>
/// A DSTU 4145 public key as carried by SubjectPublicKeyInfo (docs/signature-formats.md, section 3): the domain
/// parameters (a named curve of table Г.1 or an explicit ECBinary structure), the GOST 34.311 DKE when present and the
/// compressed point Q. <see cref="LittleEndian"/> tells which of the two key OIDs is used.
/// </summary>
public sealed class Dstu4145PublicKey
{
    private const int MaxCachedDomains = 64;
    private static readonly ConcurrentDictionary<string, Dstu4145DomainParameters> ExplicitDomains = new();

    public Dstu4145PublicKey(Dstu4145DomainParameters domain, CurvePoint q, byte[]? dke = null, bool littleEndian = true)
    {
        Domain = domain;
        Q = q;
        Dke = dke;
        LittleEndian = littleEndian;
    }

    public Dstu4145DomainParameters Domain { get; }

    public CurvePoint Q { get; }

    /// <summary>The GOST 28147 S-box table for GOST 34.311 hashing (64 bytes), or null when the key has none (DKE No. 1).</summary>
    public byte[]? Dke { get; }

    /// <summary>True for <see cref="Oids.Dstu4145Le"/>, false for <see cref="Oids.Dstu4145Be"/>.</summary>
    public bool LittleEndian { get; }

    /// <summary>Verifies a signature D (stored little-endian) over a raw hash by the national convention (section 1).</summary>
    public bool VerifyHash(ReadOnlySpan<byte> rawHash, ReadOnlySpan<byte> signature) =>
        new Dstu4145Signer(Domain).VerifyHash(Q, Reversed(rawHash), Reversed(signature));

    /// <summary>Verifies a signature over <paramref name="data"/> hashed with <paramref name="hashOid"/>, trying each of <see cref="PkiAlgorithms.CandidateHashes"/>.</summary>
    public bool VerifyData(string hashOid, byte[] data, ReadOnlySpan<byte> signature)
    {
        foreach (byte[] hash in PkiAlgorithms.CandidateHashes(hashOid, data, Dke))
        {
            if (VerifyHash(hash, signature))
                return true;
        }
        return false;
    }

    /// <summary>Hashes <paramref name="data"/> with the hash of <paramref name="signatureAlgorithm"/> (GOST 34.311 with this key's DKE) and verifies.</summary>
    public bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        VerifyHash(PkiAlgorithms.Hash(PkiAlgorithms.HashOfSignatureAlgorithm(signatureAlgorithm), data, Dke), signature);

    // ---- SubjectPublicKeyInfo ----------------------------------------------------------------------------------

    public static bool IsDstu4145(string algorithmOid) => algorithmOid is Oids.Dstu4145Le or Oids.Dstu4145Be;

    /// <summary>Parses SubjectPublicKeyInfo; the parameters are checked by section 8 and the key by 10.1.</summary>
    public static Dstu4145PublicKey FromSubjectPublicKeyInfo(Asn1Node spki)
    {
        var (domain, dke, littleEndian) = ParseAlgorithm(spki.Expect(Asn1Tag.Sequence)[0]);
        byte[] q = Asn1Node.Parse(spki[1].GetBitString()).Expect(Asn1Tag.OctetString).GetOctetString();
        if (littleEndian)
            Array.Reverse(q);
        CurvePoint point = domain.Curve.Decompress(new BigInteger(q, isUnsigned: true, isBigEndian: true));
        string? error = domain.ValidatePublicKey(point);
        if (error is not null)
            throw new InvalidDataException($"Invalid DSTU 4145 public key: {error}");
        return new Dstu4145PublicKey(domain, point, dke, littleEndian);
    }

    public byte[] ToSubjectPublicKeyInfo()
    {
        byte[] q = ToFixed(Domain.Curve.Compress(Q), (Domain.Field.M + 7) / 8, LittleEndian);
        return Der.Sequence(EncodeAlgorithm(Domain, Dke, LittleEndian), Der.BitString(Der.OctetString(q)));
    }

    /// <summary>
    /// The key AlgorithmIdentifier: <c>{ key OID, SEQUENCE { curve, DKE OPTIONAL } }</c>. Named polynomial-basis curves of
    /// table Г.1 are written by OID, any other curve explicitly.
    /// </summary>
    public static byte[] EncodeAlgorithm(Dstu4145DomainParameters domain, byte[]? dke, bool littleEndian = true)
    {
        int index = NamedCurveIndex(domain);
        byte[] curve = index >= 0 ? Der.ObjectIdentifier(Oids.NamedCurvePrefix + index) : EncodeExplicit(domain, littleEndian);
        byte[] parameters = dke is null ? Der.Sequence(curve) : Der.Sequence(curve, Der.OctetString(dke));
        return Der.Sequence(Der.ObjectIdentifier(littleEndian ? Oids.Dstu4145Le : Oids.Dstu4145Be), parameters);
    }

    /// <summary>Parses the key AlgorithmIdentifier of SubjectPublicKeyInfo or PKCS#8.</summary>
    public static (Dstu4145DomainParameters Domain, byte[]? Dke, bool LittleEndian) ParseAlgorithm(Asn1Node algorithm)
    {
        string oid = algorithm.Expect(Asn1Tag.Sequence)[0].GetOid();
        if (!IsDstu4145(oid))
            throw new NotSupportedException($"Key algorithm {oid} is not DSTU 4145.");
        bool littleEndian = oid == Oids.Dstu4145Le;
        Asn1Node parameters = algorithm[1].Expect(Asn1Tag.Sequence);
        byte[]? dke = parameters.Count > 1 ? parameters[1].Expect(Asn1Tag.OctetString).GetOctetString() : null;

        Asn1Node curve = parameters[0];
        Dstu4145DomainParameters domain = curve.Is(Asn1Tag.ObjectIdentifier)
            ? NamedCurve(curve.GetOid())
            : ParseExplicit(curve, littleEndian);
        return (domain, dke, littleEndian);
    }

    private static Dstu4145DomainParameters NamedCurve(string oid)
    {
        if (!oid.StartsWith(Oids.NamedCurvePrefix, StringComparison.Ordinal)
            || !int.TryParse(oid.AsSpan(Oids.NamedCurvePrefix.Length), out int index)
            || index < 0 || index >= Dstu4145NamedCurves.PolynomialDegrees.Count)
            throw new NotSupportedException($"Unknown DSTU 4145 named curve {oid}.");
        return Dstu4145NamedCurves.Polynomial(Dstu4145NamedCurves.PolynomialDegrees[index]);
    }

    /// <summary>The index of a curve in table Г.1, or −1 when the parameters are not one of them.</summary>
    public static int NamedCurveIndex(Dstu4145DomainParameters domain)
    {
        if (domain.Field is not PolynomialBasisField)
            return -1;
        int index = Dstu4145NamedCurves.PolynomialDegrees.ToList().IndexOf(domain.Field.M);
        return index >= 0 && SameParameters(domain, Dstu4145NamedCurves.Polynomial(domain.Field.M)) ? index : -1;
    }

    private static bool SameParameters(Dstu4145DomainParameters a, Dstu4145DomainParameters b) =>
        a.Field.Equals(b.Field)
        && a.Curve.A.ToBigInteger() == b.Curve.A.ToBigInteger()
        && a.Curve.B.ToBigInteger() == b.Curve.B.ToBigInteger()
        && a.N == b.N
        && a.BasePoint.AffineX.ToBigInteger() == b.BasePoint.AffineX.ToBigInteger()
        && a.BasePoint.AffineY.ToBigInteger() == b.BasePoint.AffineY.ToBigInteger();

    // ECBinary ::= SEQUENCE { version [0] EXPLICIT INTEGER DEFAULT 0, f BinaryField, a INTEGER, b OCTET STRING,
    //                         n INTEGER, bp OCTET STRING }
    // BinaryField ::= SEQUENCE { m INTEGER, CHOICE { k INTEGER, SEQUENCE { k, j, l } } OPTIONAL } — absent: ONB.
    private static Dstu4145DomainParameters ParseExplicit(Asn1Node ec, bool littleEndian)
    {
        string cacheKey = (littleEndian ? "le:" : "be:") + Convert.ToHexString(ec.Encoded.Span);
        if (ExplicitDomains.TryGetValue(cacheKey, out Dstu4145DomainParameters? cached))
            return cached;

        ec.Expect(Asn1Tag.Sequence);
        int i = ec[0].IsContext(0) ? 1 : 0;
        Asn1Node fieldNode = ec[i].Expect(Asn1Tag.Sequence);
        int m = fieldNode[0].GetInt32();
        // Tables 1 and 2 of DSTU 4145-2002 end at m = 509; a larger field from an untrusted certificate would only make
        // the checks of section 8 expensive.
        if (m is < 163 or > 509)
            throw new InvalidDataException($"Unsupported DSTU 4145 field degree m = {m} (tables 1 and 2 cover 163 – 509).");
        BinaryField field;
        if (fieldNode.Count == 1)
        {
            field = new OptimalNormalBasisField(m);
        }
        else if (fieldNode[1].Is(Asn1Tag.Integer))
        {
            field = new PolynomialBasisField(m, fieldNode[1].GetInt32());
        }
        else
        {
            Asn1Node p = fieldNode[1].Expect(Asn1Tag.Sequence);
            field = new PolynomialBasisField(m, p[0].GetInt32(), p[1].GetInt32(), p[2].GetInt32());
        }
        int a = ec[i + 1].GetInt32();
        byte[] b = ec[i + 2].Expect(Asn1Tag.OctetString).GetOctetString();
        BigInteger n = ec[i + 3].GetInteger();
        byte[] g = ec[i + 4].Expect(Asn1Tag.OctetString).GetOctetString();
        if (littleEndian)
        {
            Array.Reverse(b);
            Array.Reverse(g);
        }

        var curve = new BinaryCurve(field, a, new BigInteger(b, isUnsigned: true, isBigEndian: true));
        var domain = new Dstu4145DomainParameters(curve, curve.Decompress(new BigInteger(g, isUnsigned: true, isBigEndian: true)), n);

        // The parameters of table Г.1 are the same objects as the named curves; anything else is checked by section 8.
        if (field is PolynomialBasisField && Dstu4145NamedCurves.PolynomialDegrees.Contains(m)
            && SameParameters(domain, Dstu4145NamedCurves.Polynomial(m)))
        {
            domain = Dstu4145NamedCurves.Polynomial(m);
        }
        else
        {
            string? error = domain.Validate();
            if (error is not null)
                throw new InvalidDataException($"Invalid DSTU 4145 domain parameters: {error}");
        }
        if (ExplicitDomains.Count >= MaxCachedDomains)
            ExplicitDomains.Clear();
        ExplicitDomains[cacheKey] = domain;
        return domain;
    }

    private static byte[] EncodeExplicit(Dstu4145DomainParameters domain, bool littleEndian)
    {
        int bytes = (domain.Field.M + 7) / 8;
        byte[] fieldNode = domain.Field switch
        {
            PolynomialBasisField { IsTrinomial: true } pb => Der.Sequence(Der.Integer(pb.M), Der.Integer(pb.K)),
            PolynomialBasisField pb => Der.Sequence(Der.Integer(pb.M), Der.Sequence(Der.Integer(pb.K), Der.Integer(pb.J), Der.Integer(pb.L))),
            _ => Der.Sequence(Der.Integer(domain.Field.M)),
        };
        return Der.Sequence(
            fieldNode,
            Der.Integer(domain.Curve.A.IsZero ? 0 : 1),
            Der.OctetString(ToFixed(domain.Curve.B.ToBigInteger(), bytes, littleEndian)),
            Der.Integer(domain.N),
            Der.OctetString(ToFixed(domain.Curve.Compress(domain.BasePoint), bytes, littleEndian)));
    }

    /// <summary>A non-negative integer as exactly <paramref name="length"/> bytes in the requested byte order.</summary>
    public static byte[] ToFixed(BigInteger value, int length, bool littleEndian)
    {
        byte[] le = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (le.Length > length)
            throw new ArgumentException("The value does not fit into the requested length.", nameof(value));
        var result = new byte[length];
        le.CopyTo(result, 0);
        if (!littleEndian)
            Array.Reverse(result);
        return result;
    }

    internal static byte[] Reversed(ReadOnlySpan<byte> bytes)
    {
        byte[] r = bytes.ToArray();
        Array.Reverse(r);
        return r;
    }

    public override bool Equals(object? obj) => obj is Dstu4145PublicKey k && k.Q.Equals(Q);

    public override int GetHashCode() => Q.GetHashCode();
}
