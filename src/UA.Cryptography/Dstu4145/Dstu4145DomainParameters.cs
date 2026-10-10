using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Dstu4145;

/// <summary>
/// General parameters of the digital signature (DSTU 4145-2002, section 7): the field, the curve,
/// the base point P and its prime order n.
/// </summary>
public sealed class Dstu4145DomainParameters
{
    public Dstu4145DomainParameters(BinaryCurve curve, CurvePoint basePoint, BigInteger n)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(basePoint);
        if (!curve.Equals(basePoint.Curve))
            throw new ArgumentException("The base point belongs to another curve.", nameof(basePoint));
        if (n.Sign <= 0)
            throw new ArgumentOutOfRangeException(nameof(n));
        Curve = curve;
        BasePoint = basePoint;
        N = n;
    }

    public BinaryCurve Curve { get; }

    public BinaryField Field => Curve.Field;

    /// <summary>Base point P.</summary>
    public CurvePoint BasePoint { get; }

    /// <summary>Order n of the base point.</summary>
    public BigInteger N { get; }

    /// <summary>Shortest admissible signature length: the least multiple of 16 that is ≥ 2 L(n) (5.7).</summary>
    public int MinimumSignatureBits => (2 * Dstu4145Encoding.BitLength(N) + 15) / 16 * 16;

    /// <summary>
    /// 7.3: computes a base point for the curve: a random point P with nP = O.
    /// </summary>
    public static CurvePoint ComputeBasePoint(BinaryCurve curve, BigInteger n, RandomNumberGenerator? rng = null)
    {
        while (true)
        {
            CurvePoint p = curve.RandomPoint(rng);
            if (p.IsInfinity || p.AffineX.IsZero)
                continue;
            if (curve.Multiply(p, n).IsInfinity)
                return p;
        }
    }

    /// <summary>
    /// Checks the parameters as required by 8.1 – 8.3. Returns null if everything is correct,
    /// otherwise the description of the first failed condition.
    /// </summary>
    public string? Validate()
    {
        // 8.1: the field
        switch (Field)
        {
            case PolynomialBasisField pb:
                if (!Dstu4145NamedCurves.PolynomialTable.ContainsKey(pb.M))
                    return "8.1.1: the degree is not listed in table 1";
                // 8.1.2 asks for a primitive polynomial; irreducibility is checked here (primitivity needs the
                // factorization of 2^m - 1). The polynomials of table 1 are primitive by the standard.
                if (!pb.IsIrreducible())
                    return "8.1.2: the reduction polynomial is not irreducible";
                break;
            case OptimalNormalBasisField onb:
                if (!OptimalNormalBasisField.StandardDegrees.Contains(onb.M))
                    return "8.1.3: the degree is not listed in table 2";
                break;
        }

        // 8.2: the curve and the order of the base point
        if (!Curve.A.IsZero && !Curve.A.IsOne)
            return "8.2.2: A must be 0 or 1";
        if (Curve.B.IsZero)
            return "8.2.3: B must be non-zero";
        if (N.IsEven || !Primality.IsProbablePrime(N))
            return "8.2.4: n is not an odd prime";
        BigInteger sqrtField = Primality.IntegerSqrt(BigInteger.One << Field.M);
        BigInteger bound = BigInteger.Max(BigInteger.One << 160, 4 * (sqrtField + 1));
        if (N < bound)
            return "8.2.5: n is too small";
        if (!SatisfiesMovCondition(N, Field.M))
            return "8.2.6: the Menezes–Okamoto–Vanstone condition fails";

        // 8.3: the base point
        if (BasePoint.IsInfinity)
            return "8.3.2: P = O";
        if (!Curve.IsOnCurve(BasePoint))
            return "8.3.3: P does not lie on the curve";
        if (!Curve.Multiply(BasePoint, N).IsInfinity)
            return "8.3.4: nP ≠ O";

        return null;
    }

    /// <summary>6.13: 2^(mk) ≠ 1 mod n for k = 1..32.</summary>
    public static bool SatisfiesMovCondition(BigInteger n, int m)
    {
        BigInteger k = BigInteger.ModPow(2, m, n);
        BigInteger j = BigInteger.One;
        for (int i = 1; i <= 32; i++)
        {
            j = j * k % n;
            if (j.IsOne)
                return false;
        }
        return true;
    }

    /// <summary>
    /// 10.1: checks a public key. Returns null if it is correct, otherwise the description of the failed condition.
    /// </summary>
    public string? ValidatePublicKey(CurvePoint q)
    {
        ArgumentNullException.ThrowIfNull(q);
        if (!Curve.Equals(q.Curve))
            return "10.1.1: Q belongs to another curve";
        if (q.IsInfinity)
            return "10.1.2: Q = O";
        if (!Curve.IsOnCurve(q))
            return "10.1.3: Q does not lie on the curve";
        if (!Curve.Multiply(q, N).IsInfinity)
            return "10.1.4: nQ ≠ O";
        return null;
    }

    /// <summary>
    /// 6.3: random integer a with L(a) &lt; L(n), i.e. of at most L(n) − 1 bits.
    /// </summary>
    public BigInteger RandomInteger(RandomNumberGenerator? rng = null)
    {
        int bits = Dstu4145Encoding.BitLength(N) - 1;
        var bytes = new byte[(bits + 7) / 8];
        if (rng is null)
            RandomNumberGenerator.Fill(bytes);
        else
            rng.GetBytes(bytes);
        // The first generated bits become the most significant ones (6.3, step 3).
        var a = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        return a >> (8 * bytes.Length - bits);
    }

    public override string ToString() => $"{Curve}, n = {Hex.FromBigInteger(N)}";
}
