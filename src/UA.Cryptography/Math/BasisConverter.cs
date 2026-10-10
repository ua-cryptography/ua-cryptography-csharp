using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.EC;

namespace UA.Cryptography.Math;

/// <summary>
/// Change of basis between a polynomial basis and the optimal normal basis of the same GF(2^m)
/// (DSTU 4145-2002, В.6).
/// </summary>
/// <remarks>
/// <para>
/// В.6 builds the transition matrix from a root of the basis polynomial. Here the root x of the normal
/// polynomial is found in the polynomial basis without polynomial root finding: for a type 2 basis
/// x = g + 1/g where g is a primitive p-th root of unity, p = 2m + 1. Such g is z^((2^(2m) − 1)/p) for a random z
/// of GF(2^(2m)) = GF(2^m)[u]/(u^2 + u + 1) (this quadratic is irreducible because m is odd).
/// </para>
/// <para>
/// The roots of the normal polynomial are x, x^2, ..., x^(2^(m−1)); taking another root cyclically shifts every
/// element's normal basis representation. To make the conversion deterministic the root whose polynomial basis
/// representation is the smallest integer is used. Elements that differ only by such a shift
/// (Frobenius conjugates) describe isomorphic curves; see <see cref="FrobeniusShift"/>.
/// </para>
/// </remarks>
public sealed class BasisConverter
{
    private readonly ulong[][] _normalToPolynomial; // row i: x^(2^i) in the polynomial basis (standard words)
    private readonly ulong[][] _polynomialToNormal; // row k: t^k in the normal basis, as coefficients of x^(2^i)

    public BasisConverter(PolynomialBasisField polynomial, OptimalNormalBasisField normal, RandomNumberGenerator? rng = null)
        : this(polynomial, normal, FindNormalElement(polynomial, rng))
    {
    }

    private BasisConverter(PolynomialBasisField polynomial, OptimalNormalBasisField normal, FieldElement normalElement)
    {
        ArgumentNullException.ThrowIfNull(polynomial);
        ArgumentNullException.ThrowIfNull(normal);
        if (polynomial.M != normal.M)
            throw new ArgumentException("Both fields must have the same degree.");
        Polynomial = polynomial;
        Normal = normal;
        int m = polynomial.M;

        NormalElement = normalElement;

        int words = polynomial.StandardWords;
        _normalToPolynomial = new ulong[m][];
        FieldElement power = NormalElement;
        for (int i = 0; i < m; i++)
        {
            _normalToPolynomial[i] = BinaryField.BigIntegerToWords(power.ToBigInteger(), words);
            power = power.Square();
        }
        if (!power.Equals(NormalElement))
            throw new InvalidOperationException("x^(2^m) != x: the normal element is not in GF(2^m).");

        _polynomialToNormal = Invert(_normalToPolynomial, m);
    }

    public PolynomialBasisField Polynomial { get; }

    public OptimalNormalBasisField Normal { get; }

    /// <summary>The generator x of the normal basis, expressed in the polynomial basis.</summary>
    public FieldElement NormalElement { get; }

    /// <summary>Normal basis → polynomial basis.</summary>
    public FieldElement ToPolynomial(FieldElement a)
    {
        CheckField(a, Normal);
        int m = Normal.M;
        BigInteger std = a.ToBigInteger();
        var result = new ulong[Polynomial.StandardWords];
        for (int j = 0; j < m; j++)
        {
            // standard bit j of the normal basis representation is the coefficient of x^(2^(m-1-j))
            if (!((std >> j) & 1).IsZero)
                Gf2Poly.Xor(result, _normalToPolynomial[m - 1 - j]);
        }
        return Polynomial.FromBigInteger(BinaryField.WordsToBigInteger(result));
    }

    /// <summary>Polynomial basis → normal basis.</summary>
    public FieldElement ToNormal(FieldElement a)
    {
        CheckField(a, Polynomial);
        int m = Polynomial.M;
        BigInteger std = a.ToBigInteger();
        var coefficients = new ulong[(m + 63) >> 6]; // bit i: coefficient of x^(2^i)
        for (int k = 0; k < m; k++)
        {
            if (!((std >> k) & 1).IsZero)
                Gf2Poly.Xor(coefficients, _polynomialToNormal[k]);
        }
        BigInteger result = BigInteger.Zero;
        for (int i = 0; i < m; i++)
        {
            if (Gf2Poly.TestBit(coefficients, i))
                result |= BigInteger.One << (m - 1 - i);
        }
        return Normal.FromBigInteger(result);
    }

    /// <summary>Maps a curve to the other basis (the coefficient A ∈ {0, 1} is preserved).</summary>
    public BinaryCurve Convert(BinaryCurve curve)
    {
        ArgumentNullException.ThrowIfNull(curve);
        if (curve.Field.Equals(Polynomial))
            return new BinaryCurve(Normal, curve.A.IsZero ? Normal.Zero : Normal.One, ToNormal(curve.B));
        if (curve.Field.Equals(Normal))
            return new BinaryCurve(Polynomial, curve.A.IsZero ? Polynomial.Zero : Polynomial.One, ToPolynomial(curve.B));
        throw new ArgumentException("The curve is defined over neither field of this converter.");
    }

    /// <summary>Maps a point to the image <paramref name="target"/> of its curve (see <see cref="Convert(BinaryCurve)"/>).</summary>
    public CurvePoint Convert(CurvePoint point, BinaryCurve target)
    {
        ArgumentNullException.ThrowIfNull(point);
        ArgumentNullException.ThrowIfNull(target);
        if (point.IsInfinity)
            return target.Infinity;
        Func<FieldElement, FieldElement> map = point.Curve.Field.Equals(Polynomial) ? ToNormal : ToPolynomial;
        return target.CreatePoint(map(point.AffineX), map(point.AffineY));
    }

    /// <summary>
    /// Returns a converter that uses another root of the normal polynomial, chosen so that
    /// <paramref name="polynomialValue"/> maps exactly to <paramref name="normalValue"/>.
    /// Use it to reproduce the conversion behind published tables, e.g. align table Г.1 with table Г.2
    /// by the curve coefficient B.
    /// </summary>
    public BasisConverter AlignedTo(FieldElement polynomialValue, FieldElement normalValue)
    {
        CheckField(polynomialValue, Polynomial);
        CheckField(normalValue, Normal);
        int shift = FrobeniusShift(ToNormal(polynomialValue), normalValue);
        if (shift < 0)
            throw new ArgumentException("The values are not Frobenius conjugates of each other under any change of basis.");

        // With the root x' = x^(2^s) the normal basis coordinates rotate: ToNormal'(a) = ToNormal(a)^(2^-s).
        // We need ToNormal'(v) = ToNormal(v)^(2^shift), so x' = x^(2^(m - shift)).
        return new BasisConverter(Polynomial, Normal, NormalElement.SquareTimes((Polynomial.M - shift) % Polynomial.M));
    }

    /// <summary>
    /// Returns j such that b = a^(2^j) (in the normal basis: b is a cyclic shift right of a by j), or −1.
    /// </summary>
    public static int FrobeniusShift(FieldElement a, FieldElement b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        FieldElement x = a;
        for (int j = 0; j < a.Field.M; j++)
        {
            if (x.Equals(b))
                return j;
            x = x.Square();
        }
        return -1;
    }

    /// <summary>
    /// The normal polynomial of В.2: q(t) = 1, p(t) = t + 1, then m − 1 times r = q, q = p, p = t q + r.
    /// Coefficient of t^i is bit i of the result.
    /// </summary>
    public static BigInteger NormalPolynomial(int m)
    {
        BigInteger q = BigInteger.One, p = 3; // t + 1
        for (int i = 1; i < m; i++)
        {
            BigInteger r = q;
            q = p;
            p = (q << 1) ^ r;
        }
        return p;
    }

    private static FieldElement FindNormalElement(PolynomialBasisField field, RandomNumberGenerator? rng)
    {
        int m = field.M;
        int p = 2 * m + 1;
        BigInteger exponent = ((BigInteger.One << (2 * m)) - 1) / p;

        while (true)
        {
            var z = new Quadratic(field.Random(rng), field.Random(rng));
            if (z.IsZero)
                continue;
            Quadratic g = z.Pow(exponent);
            if (g.IsOne)
                continue; // need an element of order exactly p (p is prime)
            Quadratic sum = g + g.Pow(p - 1); // g + 1/g
            if (!sum.Hi.IsZero)
                throw new InvalidOperationException("g + 1/g is not in GF(2^m).");

            // Deterministic choice among the conjugates: the smallest integer representation.
            FieldElement best = sum.Lo, x = sum.Lo;
            for (int j = 1; j < m; j++)
            {
                x = x.Square();
                if (x.ToBigInteger() < best.ToBigInteger())
                    best = x;
            }
            return best;
        }
    }

    /// <summary>Gauss–Jordan inversion of an m × m matrix over GF(2) given by rows (bit k of row i = M[i, k]).</summary>
    private static ulong[][] Invert(ulong[][] rows, int m)
    {
        int words = (m + 63) >> 6;
        var a = rows.Select(r => (ulong[])r.Clone()).ToArray();
        var inv = new ulong[m][];
        for (int i = 0; i < m; i++)
        {
            inv[i] = new ulong[words];
            Gf2Poly.FlipBit(inv[i], i);
        }

        for (int col = 0; col < m; col++)
        {
            int pivot = -1;
            for (int r = col; r < m; r++)
            {
                if (Gf2Poly.TestBit(a[r], col))
                {
                    pivot = r;
                    break;
                }
            }
            if (pivot < 0)
                throw new InvalidOperationException("The conjugates of x are linearly dependent: not a normal basis.");
            (a[col], a[pivot]) = (a[pivot], a[col]);
            (inv[col], inv[pivot]) = (inv[pivot], inv[col]);
            for (int r = 0; r < m; r++)
            {
                if (r != col && Gf2Poly.TestBit(a[r], col))
                {
                    Gf2Poly.Xor(a[r], a[col]);
                    Gf2Poly.Xor(inv[r], inv[col]);
                }
            }
        }

        // The same row operations turned [R | I] into [I | R^-1]; row k of R^-1 holds t^k in the normal basis.
        return inv;
    }

    private static void CheckField(FieldElement a, BinaryField expected)
    {
        ArgumentNullException.ThrowIfNull(a);
        if (!a.Field.Equals(expected))
            throw new ArgumentException("The element belongs to another field.");
    }

    /// <summary>Element lo + hi·u of GF(2^(2m)) = GF(2^m)[u]/(u^2 + u + 1).</summary>
    private readonly record struct Quadratic(FieldElement Lo, FieldElement Hi)
    {
        public bool IsZero => Lo.IsZero && Hi.IsZero;

        public bool IsOne => Lo.IsOne && Hi.IsZero;

        public static Quadratic operator +(Quadratic a, Quadratic b) => new(a.Lo + b.Lo, a.Hi + b.Hi);

        // (a0 + a1 u)(b0 + b1 u) = a0 b0 + a1 b1 + (a0 b1 + a1 b0 + a1 b1) u, since u^2 = u + 1
        public static Quadratic operator *(Quadratic a, Quadratic b)
        {
            FieldElement t0 = a.Lo * b.Lo, t1 = a.Hi * b.Hi, t2 = (a.Lo + a.Hi) * (b.Lo + b.Hi);
            return new Quadratic(t0 + t1, t2 + t0);
        }

        public Quadratic Pow(BigInteger e)
        {
            Quadratic result = new(Lo.Field.One, Lo.Field.Zero);
            for (int i = (int)e.GetBitLength() - 1; i >= 0; i--)
            {
                result *= result;
                if (!((e >> i) & 1).IsZero)
                    result *= this;
            }
            return result;
        }
    }
}
