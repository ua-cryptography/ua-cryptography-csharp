namespace UA.Cryptography.Math;

/// <summary>
/// GF(2^m) in the Gaussian optimal normal basis of type 2 (DSTU 4145-2002, В.2, В.4, table 2).
/// </summary>
/// <remarks>
/// <para>
/// <b>Standard representation.</b> The basis is (x, x^2, x^4, ..., x^(2^(m-1))). Following 5.3, the leftmost
/// (most significant) bit of the m-bit string is the coefficient of x and the rightmost (least significant)
/// bit is the coefficient of x^(2^(m-1)); squaring is a cyclic shift right and the unit is the all-ones string.
/// </para>
/// <para>
/// <b>Why the textbook algorithm is slow.</b> The multiplication of В.4 evaluates one bit of the product per
/// bilinear form z = x M y^T and repeats it m times with rotated inputs: O(m^2) single-bit operations.
/// The 2010 implementation this library replaces did exactly that, bit by bit, which is why it was
/// thousands of times slower than the polynomial basis.
/// </para>
/// <para>
/// <b>What is done here.</b> For a type 2 basis p = 2m + 1 is prime and x = g + 1/g, where g is a primitive
/// p-th root of unity. Put s_k = g^k + g^(-k). Then s_k = s_(p-k), s_0 = 0, and the normal basis is a
/// permutation of (s_1, ..., s_m): x^(2^i) = s_(2^i mod p), folded into 1..m. In this permuted basis
/// <code>s_i * s_j = s_(i+j) + s_|i-j|</code>
/// so a product is obtained from two ordinary carry-less polynomial products,
/// A(t)B(t) and A(t)B*(t) with B* the bit-reversal of B, followed by a cheap "folding" of exponents
/// (Blake, Roth, Seroussi; Wu, Hasan, Blake, Gao — "palindromic" / "permuted" representation).
/// Squaring maps s_k to s_2k, i.e. a bit spread followed by the same folding.
/// The cost becomes the same as in the polynomial basis: a few dozen word multiplications for m ≤ 509.
/// </para>
/// <para>
/// Internally, coefficient of s_k is stored at bit k (k = 1..m), bit 0 is always zero.
/// The permutation to and from the standard representation is applied only when elements enter or leave
/// the field (<see cref="BinaryField.FromBigInteger"/>, <see cref="FieldElement.ToBigInteger"/>).
/// </para>
/// </remarks>
public sealed class OptimalNormalBasisField : BinaryField
{
    /// <summary>Degrees of table 2 of DSTU 4145-2002.</summary>
    public static readonly IReadOnlyList<int> StandardDegrees =
        new[] { 173, 179, 191, 233, 239, 251, 281, 293, 359, 419, 431, 443, 491, 509 };

    // _position[i] = internal bit holding the coefficient of x^(2^i).
    private readonly int[] _position;
    private readonly int[] _exponentOfPosition; // inverse map: internal bit k -> i

    public OptimalNormalBasisField(int m)
        : base(m, (m + 1 + 63) >> 6)
    {
        if (!HasTypeTwoBasis(m))
            throw new ArgumentException($"GF(2^{m}) has no optimal normal basis of type 2.", nameof(m));

        int p = 2 * m + 1;
        _position = new int[m];
        _exponentOfPosition = new int[m + 1];
        int power = 1;
        for (int i = 0; i < m; i++)
        {
            int k = power <= m ? power : p - power;
            _position[i] = k;
            _exponentOfPosition[k] = i;
            power = 2 * power % p;
        }
    }

    public override FieldBasis Basis => FieldBasis.OptimalNormal;

    /// <summary>
    /// True when p = 2m + 1 is prime and the order k of 2 modulo p is k = 2m (2 is primitive), or p ≡ 3 (mod 4)
    /// and k = m.
    /// </summary>
    /// <remarks>
    /// В.2 of the standard states the first case as "p ≡ 1 (mod 4) and k = 2m". That is too strict: for m = 173,
    /// the degree of the standard's own example Б.2, p = 347 ≡ 3 (mod 4) and k = 346 = 2m. A type 2 basis exists
    /// whenever 2 is primitive modulo p, whatever p mod 4 is (Mullin et al., ref. [11] of the standard).
    /// </remarks>
    public static bool HasTypeTwoBasis(int m)
    {
        int p = 2 * m + 1;
        if (m < 2 || !IsPrime(p))
            return false;
        int order = 1;
        for (long v = 2; v != 1; v = v * 2 % p)
            order++;
        return order == 2 * m || (p % 4 == 3 && order == m);
    }

    internal override void SetOne(Span<ulong> r)
    {
        // 1 = sum of all basis elements (5.3): every s_1..s_m.
        r.Clear();
        for (int k = 1; k <= M; k++)
            Gf2Poly.FlipBit(r, k);
    }

    internal override void FromStandard(ReadOnlySpan<ulong> std, Span<ulong> r)
    {
        r.Clear();
        // Standard bit j is the coefficient of x^(2^(m-1-j)).
        for (int j = 0; j < M; j++)
        {
            if (Gf2Poly.TestBit(std, j))
                Gf2Poly.FlipBit(r, _position[M - 1 - j]);
        }
    }

    internal override void ToStandard(ReadOnlySpan<ulong> a, Span<ulong> std)
    {
        std.Clear();
        for (int k = 1; k <= M; k++)
        {
            if (Gf2Poly.TestBit(a, k))
                Gf2Poly.FlipBit(std, M - 1 - _exponentOfPosition[k]);
        }
    }

    internal override void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        int w = Words;
        int m = M;
        Span<ulong> bReflected = stackalloc ulong[w];
        Span<ulong> p1 = stackalloc ulong[2 * w];
        Span<ulong> p2 = stackalloc ulong[2 * w];
        Span<ulong> h = stackalloc ulong[w];
        Span<ulong> t = stackalloc ulong[w];

        // a = sum a_i s_i, b = sum b_j s_j, i, j in 1..m.
        // P1 = A(t) B(t):  coefficient of t^(i+j)      -> s_(i+j)
        // P2 = A(t) B*(t): coefficient of t^(m+1+i-j)  -> s_|i-j|   (B*(t) = t^(m+1) B(1/t))
        Reflect(b.Slice(0, w), bReflected);
        Gf2Poly.Multiply(a.Slice(0, w), b.Slice(0, w), p1);
        Gf2Poly.Multiply(a.Slice(0, w), bReflected, p2);

        // Exponents that land on s_u with u = m+1-e after folding:
        //   P1, e = i+j-m in 1..m  (s_(i+j) = s_(p-i-j) when i+j > m)
        //   P2, e = m+1+i-j in 2..m (i < j)
        Gf2Poly.ShiftRight(p1, m, h);
        Gf2Poly.Xor(h, p2.Slice(0, w));
        KeepBits1ToM(h);
        Reflect(h, t);

        // Exponents that land directly:
        //   P1, i+j <= m;  P2, m+1+i-j > m+1 -> s_(i-j).
        Gf2Poly.ShiftRight(p2, m + 1, r.Slice(0, w));
        Gf2Poly.Xor(r.Slice(0, w), p1.Slice(0, w));
        Gf2Poly.Xor(r.Slice(0, w), t);
        KeepBits1ToM(r.Slice(0, w));
    }

    internal override void Square(ReadOnlySpan<ulong> a, Span<ulong> r)
    {
        int w = Words;
        Span<ulong> s = stackalloc ulong[2 * w];
        Span<ulong> h = stackalloc ulong[w];
        Span<ulong> t = stackalloc ulong[w];

        // s_k^2 = s_2k; exponents 2k > m fold to p - 2k.
        Gf2Poly.Square(a.Slice(0, w), s);
        Gf2Poly.ShiftRight(s, M, h);
        KeepBits1ToM(h);
        Reflect(h, t);

        s.Slice(0, w).CopyTo(r);
        Gf2Poly.Xor(r.Slice(0, w), t);
        KeepBits1ToM(r.Slice(0, w));
    }

    /// <summary>The trace of every normal basis element is 1, so tr(a) is the parity of the coordinates.</summary>
    internal override int Trace(ReadOnlySpan<ulong> a) => Gf2Poly.Parity(a.Slice(0, Words));

    /// <summary>dst bit (m+1-u) = src bit u for u = 1..m. src must have bit 0 and bits above m cleared.</summary>
    private void Reflect(ReadOnlySpan<ulong> src, Span<ulong> dst)
    {
        int w = Words;
        Span<ulong> rev = stackalloc ulong[w];
        Gf2Poly.ReverseWords(src.Slice(0, w), rev); // bit u -> 64w - 1 - u
        int shift = 64 * w - 2 - M;                 // move 64w - 1 - u to m + 1 - u
        if (shift >= 0)
            Gf2Poly.ShiftRight(rev, shift, dst.Slice(0, w));
        else
            Gf2Poly.ShiftLeft(rev, -shift, dst.Slice(0, w));
    }

    private void KeepBits1ToM(Span<ulong> a)
    {
        a[0] &= ~1UL;
        Gf2Poly.ClearAbove(a, M + 1);
    }

    private static bool IsPrime(int n)
    {
        if (n < 2)
            return false;
        for (int d = 2; d * d <= n; d++)
        {
            if (n % d == 0)
                return false;
        }
        return true;
    }

    public override bool Equals(object? obj) => obj is OptimalNormalBasisField f && f.M == M;

    public override int GetHashCode() => HashCode.Combine(M, 2);

    public override string ToString() => $"GF(2^{M}), optimal normal basis (type 2)";
}
