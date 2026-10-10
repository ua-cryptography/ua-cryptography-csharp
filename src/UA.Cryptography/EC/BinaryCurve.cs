using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.Math;

namespace UA.Cryptography.EC;

/// <summary>
/// Elliptic curve y^2 + xy = x^3 + A x^2 + B over GF(2^m), A ∈ {0, 1}, B ≠ 0 (DSTU 4145-2002, 5.4).
/// </summary>
/// <remarks>
/// The class does not depend on the basis: every formula is written in terms of field operations, so the same
/// code serves the polynomial and the optimal normal basis.
/// </remarks>
public sealed class BinaryCurve : IEquatable<BinaryCurve>
{
    private readonly ulong[] _sqrtB; // internal representation of sqrt(B), used by the Montgomery ladder

    public BinaryCurve(BinaryField field, FieldElement a, FieldElement b)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (!a.Field.Equals(field) || !b.Field.Equals(field))
            throw new ArgumentException("Curve coefficients must belong to the given field.");
        if (!a.IsZero && !a.IsOne)
            throw new ArgumentException("Coefficient A must be 0 or 1 (DSTU 4145-2002, 5.4).", nameof(a));
        if (b.IsZero)
            throw new ArgumentException("Coefficient B must be non-zero.", nameof(b));

        Field = field;
        A = a;
        B = b;
        Infinity = new CurvePoint(this, null, null);
        _sqrtB = b.Sqrt().Value.ToArray();
    }

    public BinaryCurve(BinaryField field, int a, BigInteger b)
        : this(field, a switch
        {
            0 => field.Zero,
            1 => field.One,
            _ => throw new ArgumentOutOfRangeException(nameof(a), "A must be 0 or 1."),
        }, field.FromBigInteger(b))
    {
    }

    public BinaryField Field { get; }

    public FieldElement A { get; }

    public FieldElement B { get; }

    /// <summary>The point at infinity O, neutral element of the group.</summary>
    public CurvePoint Infinity { get; }

    /// <summary>Creates a point and checks that it lies on the curve.</summary>
    public CurvePoint CreatePoint(FieldElement x, FieldElement y)
    {
        var p = new CurvePoint(this, x, y);
        if (!x.Field.Equals(Field) || !y.Field.Equals(Field) || !IsOnCurve(p))
            throw new ArgumentException("The point does not lie on the curve.");
        return p;
    }

    /// <summary>Creates a point from the standard representations of its coordinates and checks it.</summary>
    public CurvePoint CreatePoint(BigInteger x, BigInteger y) => CreatePoint(Field.FromBigInteger(x), Field.FromBigInteger(y));

    public CurvePoint CreatePoint(string xHex, string yHex) => CreatePoint(Field.FromHex(xHex), Field.FromHex(yHex));

    /// <summary>y^2 + xy = x^3 + A x^2 + B.</summary>
    public bool IsOnCurve(CurvePoint p)
    {
        if (p.IsInfinity)
            return true;
        FieldElement x = p.AffineX, y = p.AffineY;
        FieldElement x2 = x.Square();
        FieldElement lhs = y.Square() + x * y;
        FieldElement rhs = x2 * x + A * x2 + B;
        return lhs.Equals(rhs);
    }

    // --------------------------------------------------------------------------------------------
    // Group law in affine coordinates (DSTU 4145-2002, В.7, В.8)
    // --------------------------------------------------------------------------------------------

    /// <summary>-P = (x, x + y).</summary>
    public CurvePoint Negate(CurvePoint p)
    {
        CheckPoint(p);
        return p.IsInfinity ? p : new CurvePoint(this, p.X, p.X! + p.Y!);
    }

    public CurvePoint Add(CurvePoint p, CurvePoint q)
    {
        CheckPoint(p);
        CheckPoint(q);
        if (p.IsInfinity)
            return q;
        if (q.IsInfinity)
            return p;

        FieldElement x1 = p.AffineX, y1 = p.AffineY, x2 = q.AffineX, y2 = q.AffineY;
        if (x1.Equals(x2))
        {
            // Either Q = P (doubling) or Q = -P (sum is O).
            return y1.Equals(y2) ? Double(p) : Infinity;
        }

        // Note: the second formula of В.8 has a misprint "(x_P + y_Q)" in the denominator; it must be x_P + x_Q.
        FieldElement xSum = x1 + x2;
        FieldElement lambda = (y1 + y2) / xSum;
        FieldElement x3 = lambda.Square() + lambda + xSum + A;
        FieldElement y3 = lambda * (x1 + x3) + x3 + y1;
        return new CurvePoint(this, x3, y3);
    }

    public CurvePoint Double(CurvePoint p)
    {
        CheckPoint(p);
        if (p.IsInfinity)
            return p;
        FieldElement x = p.AffineX, y = p.AffineY;
        if (x.IsZero)
            return Infinity; // the only point of order 2: (0, sqrt(B))

        FieldElement x2 = x.Square();
        FieldElement xr = x2 + B / x2;
        FieldElement yr = x2 + (x + y / x) * xr + xr;
        return new CurvePoint(this, xr, yr);
    }

    // --------------------------------------------------------------------------------------------
    // Scalar multiplication
    // --------------------------------------------------------------------------------------------

    /// <summary>
    /// kP by the Montgomery ladder in López–Dahab projective x-only coordinates
    /// (J. López, R. Dahab, "Fast multiplication on elliptic curves over GF(2^m) without precomputation", CHES 1999).
    /// </summary>
    /// <remarks>
    /// Each bit of k costs the same 6 multiplications and 5 squarings regardless of its value, and the only
    /// inversion happens once at the end, when y is recovered. Compare with В.8, where every addition and doubling
    /// in affine coordinates needs an inversion (≈ 10 multiplications by Itoh–Tsujii).
    /// </remarks>
    public CurvePoint Multiply(CurvePoint p, BigInteger k)
    {
        CheckPoint(p);
        if (k.Sign < 0)
            return Multiply(Negate(p), -k);
        if (k.IsZero || p.IsInfinity)
            return Infinity;
        if (p.AffineX.IsZero)
            return k.IsEven ? Infinity : p; // point of order 2

        return Ladder(p, k, (int)k.GetBitLength());
    }

    /// <summary>
    /// kP for a point P of known prime order n with a fixed number of ladder steps, so that the running time
    /// does not reveal the bit length of the secret scalar (used for private keys and the nonce e).
    /// </summary>
    internal CurvePoint MultiplyFixedLength(CurvePoint p, BigInteger k, BigInteger order)
    {
        CheckPoint(p);
        if (p.IsInfinity || order.Sign <= 0)
            throw new ArgumentException("A finite point of known order is required.");
        k = BigInteger.Remainder(k, order);
        if (k.Sign < 0)
            k += order;
        if (k.IsZero)
            return Infinity;

        // k' = k + n or k + 2n has exactly L(n) + 1 bits and k'P = kP.
        int bits = (int)order.GetBitLength() + 1;
        BigInteger kk = k + order;
        if (kk.GetBitLength() < bits)
            kk += order;
        return Ladder(p, kk, bits);
    }

    private CurvePoint Ladder(CurvePoint p, BigInteger k, int bits)
    {
        BinaryField f = Field;
        int w = f.Words;
        ReadOnlySpan<ulong> x = p.AffineX.Value;

        Span<ulong> x1 = stackalloc ulong[w];
        Span<ulong> z1 = stackalloc ulong[w];
        Span<ulong> x2 = stackalloc ulong[w];
        Span<ulong> z2 = stackalloc ulong[w];
        Span<ulong> t1 = stackalloc ulong[w];
        Span<ulong> t2 = stackalloc ulong[w];

        // (X1 : Z1) = P, (X2 : Z2) = 2P
        x.CopyTo(x1);
        f.SetOne(z1);
        f.Square(x, z2);            // Z2 = x^2
        f.Square(z2, x2);           // x^4
        BinaryField.Add(x2, B.Value, x2); // X2 = x^4 + B

        byte[] scalar = k.ToByteArray(isUnsigned: true, isBigEndian: false);
        ulong swap = 0;
        for (int i = bits - 2; i >= 0; i--)
        {
            ulong bit = (ulong)((i >> 3) < scalar.Length ? (scalar[i >> 3] >> (i & 7)) & 1 : 0);
            swap ^= bit;
            ConditionalSwap(x1, x2, swap);
            ConditionalSwap(z1, z2, swap);
            swap = bit;

            // (X2 : Z2) <- R0 + R1 (their difference is P), (X1 : Z1) <- 2 R0
            MontgomeryAdd(x2, z2, x1, z1, x, t1, t2);
            MontgomeryDouble(x1, z1, t1, t2);
        }
        ConditionalSwap(x1, x2, swap);
        ConditionalSwap(z1, z2, swap);

        return RecoverAffine(p, x1, z1, x2, z2);
    }

    /// <summary>(Xa : Za) &lt;- (Xa : Za) + (Xb : Zb), given that their difference has affine x-coordinate x.</summary>
    private void MontgomeryAdd(Span<ulong> xa, Span<ulong> za, ReadOnlySpan<ulong> xb, ReadOnlySpan<ulong> zb,
        ReadOnlySpan<ulong> x, Span<ulong> t1, Span<ulong> t2)
    {
        BinaryField f = Field;
        f.Multiply(xa, zb, t1);       // T1 = Xa Zb
        f.Multiply(xb, za, t2);       // T2 = Xb Za
        BinaryField.Add(t1, t2, za);
        f.Square(za, za);             // Za = (Xa Zb + Xb Za)^2
        f.Multiply(t1, t2, t1);       // T1 = Xa Zb Xb Za
        f.Multiply(x, za, xa);
        BinaryField.Add(xa, t1, xa);  // Xa = x Za + T1
    }

    /// <summary>(X : Z) &lt;- 2 (X : Z): X = X^4 + B Z^4 = (X^2 + sqrt(B) Z^2)^2, Z = X^2 Z^2.</summary>
    private void MontgomeryDouble(Span<ulong> x, Span<ulong> z, Span<ulong> t1, Span<ulong> t2)
    {
        BinaryField f = Field;
        f.Square(x, t1);              // X^2
        f.Square(z, t2);              // Z^2
        f.Multiply(t1, t2, z);        // Z = X^2 Z^2
        f.Multiply(t2, _sqrtB, t2);   // sqrt(B) Z^2
        BinaryField.Add(t1, t2, x);
        f.Square(x, x);
    }

    /// <summary>
    /// Recovers the affine kP from (X1 : Z1) = kP, (X2 : Z2) = (k+1)P and P = (x, y) (López–Dahab, Mxy).
    /// </summary>
    private CurvePoint RecoverAffine(CurvePoint p, ReadOnlySpan<ulong> x1, ReadOnlySpan<ulong> z1,
        ReadOnlySpan<ulong> x2, ReadOnlySpan<ulong> z2)
    {
        if (Gf2Poly.IsZero(z1))
            return Infinity;
        if (Gf2Poly.IsZero(z2))
            return Negate(p); // (k+1)P = O, so kP = -P

        BinaryField f = Field;
        int w = f.Words;
        ReadOnlySpan<ulong> x = p.AffineX.Value;
        ReadOnlySpan<ulong> y = p.AffineY.Value;

        Span<ulong> t3 = stackalloc ulong[w];
        Span<ulong> t4 = stackalloc ulong[w];
        Span<ulong> a = stackalloc ulong[w];
        Span<ulong> b = stackalloc ulong[w];
        var xk = new ulong[w];
        var yk = new ulong[w];

        f.Multiply(z1, z2, t3);          // T3 = Z1 Z2
        f.Multiply(z1, x, a);
        BinaryField.Add(a, x1, a);       // a = X1 + x Z1
        f.Multiply(z2, x, b);
        f.Multiply(b, x1, xk);           // X1 x Z2 (becomes x_k after division)
        BinaryField.Add(b, x2, b);       // b = X2 + x Z2
        f.Multiply(a, b, b);             // (X1 + x Z1)(X2 + x Z2)
        f.Square(x, t4);
        BinaryField.Add(t4, y, t4);      // x^2 + y
        f.Multiply(t4, t3, t4);          // (x^2 + y) Z1 Z2
        BinaryField.Add(t4, b, t4);      // numerator
        f.Multiply(t3, x, t3);           // x Z1 Z2
        f.Invert(t3, t3);
        f.Multiply(t4, t3, t4);
        f.Multiply(xk, t3, xk);          // x_k = X1 / Z1
        BinaryField.Add(xk, x, a);       // x_k + x
        f.Multiply(a, t4, yk);
        BinaryField.Add(yk, y, yk);      // y_k

        return new CurvePoint(this, new FieldElement(f, xk), new FieldElement(f, yk));
    }

    private static void ConditionalSwap(Span<ulong> a, Span<ulong> b, ulong swap)
    {
        ulong mask = 0UL - swap;
        for (int i = 0; i < a.Length; i++)
        {
            ulong t = (a[i] ^ b[i]) & mask;
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    /// <summary>kP computed by the plain double-and-add of В.8 in affine coordinates (reference implementation).</summary>
    public CurvePoint MultiplyDoubleAndAdd(CurvePoint p, BigInteger k)
    {
        if (k.Sign < 0)
            return MultiplyDoubleAndAdd(Negate(p), -k);
        CurvePoint q = Infinity;
        for (int i = (int)k.GetBitLength() - 1; i >= 0; i--)
        {
            q = Double(q);
            if (!((k >> i) & 1).IsZero)
                q = Add(q, p);
        }
        return q;
    }

    // --------------------------------------------------------------------------------------------
    // Points: random point, compression (DSTU 4145-2002, 6.8 – 6.10)
    // --------------------------------------------------------------------------------------------

    /// <summary>Random point of the curve (6.8).</summary>
    public CurvePoint RandomPoint(RandomNumberGenerator? rng = null)
    {
        int w = Field.Words;
        Span<ulong> z = stackalloc ulong[w];
        while (true)
        {
            FieldElement u = Field.Random(rng);
            FieldElement u2 = u.Square();
            FieldElement rhs = u2 * u + A * u2 + B; // w = u^3 + A u^2 + B
            if (Field.SolveQuadratic(u.Value, rhs.Value, z) == 0)
                continue;
            return new CurvePoint(this, u, new FieldElement(Field, z.ToArray()));
        }
    }

    /// <summary>
    /// Point compression (6.9): the least significant bit of x_P is replaced by tr(y_P / x_P).
    /// Returns the standard representation of the compressed point; 0 stands for a point with x_P = 0.
    /// </summary>
    public BigInteger Compress(CurvePoint p)
    {
        CheckPoint(p);
        if (p.IsInfinity || p.AffineX.IsZero)
            return BigInteger.Zero;
        int i = (p.AffineY / p.AffineX).Trace();
        BigInteger x = p.AffineX.ToBigInteger();
        BigInteger compressed = (x & ~BigInteger.One) | i;
        if (compressed.IsZero)
        {
            // x = 1 (as a bit string) with tr(y/x) = 0 compresses to 0, which 6.10 decodes as (0, sqrt(B)):
            // a gap in the standard. Such a point (probability about 2^-m) cannot be represented compressed.
            throw new ArgumentException("This point has no unambiguous compressed form (6.9 maps it to 0).", nameof(p));
        }
        return compressed;
    }

    /// <summary>Point decompression (6.10). Throws if the value does not encode a point of this curve.</summary>
    public CurvePoint Decompress(BigInteger compressed)
    {
        if (compressed.IsZero)
            return new CurvePoint(this, Field.Zero, B.Sqrt());

        int k = (int)(compressed & BigInteger.One);
        FieldElement x = Field.FromBigInteger(compressed & ~BigInteger.One);
        int traceA = A.IsZero ? 0 : 1;
        if (x.Trace() != traceA)
            x = Field.FromBigInteger(compressed | BigInteger.One);
        if (x.IsZero)
            throw new ArgumentException("The value does not encode a point of the curve.", nameof(compressed));

        FieldElement x2 = x.Square();
        FieldElement rhs = x2 * x + A * x2 + B;
        FieldElement v = rhs / x2;
        var z = new ulong[Field.Words];
        if (Field.SolveQuadratic(Field.One.Value, v.Value, z) == 0)
            throw new ArgumentException("The value does not encode a point of the curve.", nameof(compressed));
        var zz = new FieldElement(Field, z);
        FieldElement y = zz.Trace() == k ? zz * x : (zz + Field.One) * x;
        return new CurvePoint(this, x, y);
    }

    private void CheckPoint(CurvePoint p)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (!ReferenceEquals(p.Curve, this) && !p.Curve.Equals(this))
            throw new ArgumentException("The point belongs to another curve.");
    }

    public bool Equals(BinaryCurve? other) =>
        other is not null && (ReferenceEquals(this, other) ||
                              (Field.Equals(other.Field) && A.Equals(other.A) && B.Equals(other.B)));

    public override bool Equals(object? obj) => obj is BinaryCurve c && Equals(c);

    public override int GetHashCode() => HashCode.Combine(Field.M, B);

    public override string ToString() => $"y^2 + xy = x^3 + {(A.IsZero ? "" : "x^2 + ")}{B.ToHex()} over {Field}";
}
