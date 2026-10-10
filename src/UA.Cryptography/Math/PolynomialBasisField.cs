namespace UA.Cryptography.Math;

/// <summary>
/// GF(2^m) in the polynomial basis defined by a trinomial t^m + t^k + 1
/// or a pentanomial t^m + t^l + t^j + t^k + 1, 0 &lt; k &lt; j &lt; l &lt; m (DSTU 4145-2002, 5.2).
/// </summary>
/// <remarks>
/// Elements are stored exactly as in the standard: bit i is the coefficient of t^i.
/// Multiplication is a carry-less product followed by word-level reduction (В.3).
/// </remarks>
public sealed class PolynomialBasisField : BinaryField
{
    private readonly int[] _terms; // exponents of the reduction polynomial below m, including 0

    /// <param name="m">Extension degree.</param>
    /// <param name="k">Smallest non-zero exponent of the reduction polynomial.</param>
    /// <param name="j">Middle exponent of a pentanomial, 0 for a trinomial.</param>
    /// <param name="l">Largest exponent below m of a pentanomial, 0 for a trinomial.</param>
    public PolynomialBasisField(int m, int k, int j = 0, int l = 0)
        : base(m, (m + 63) >> 6)
    {
        if (k <= 0 || k >= m)
            throw new ArgumentOutOfRangeException(nameof(k), "k must satisfy 0 < k < m.");
        if (j == 0 && l == 0)
        {
            _terms = new[] { 0, k };
        }
        else
        {
            if (!(k < j && j < l && l < m))
                throw new ArgumentException("A pentanomial requires 0 < k < j < l < m.");
            _terms = new[] { 0, k, j, l };
        }

        // Word-level reduction folds a whole word below position m in one step; this needs the
        // middle terms to be well below m, which holds for every polynomial of table 1.
        if (_terms[^1] > m - 64)
            throw new ArgumentException("The reduction polynomial's middle terms must be below m - 64.");

        K = k;
        J = j;
        L = l;
    }

    public override FieldBasis Basis => FieldBasis.Polynomial;

    public int K { get; }

    public int J { get; }

    public int L { get; }

    public bool IsTrinomial => J == 0;

    internal override void SetOne(Span<ulong> r)
    {
        r.Clear();
        r[0] = 1;
    }

    internal override void FromStandard(ReadOnlySpan<ulong> std, Span<ulong> r) => std.Slice(0, Words).CopyTo(r);

    internal override void ToStandard(ReadOnlySpan<ulong> a, Span<ulong> std) => a.Slice(0, Words).CopyTo(std);

    internal override void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        Span<ulong> c = stackalloc ulong[2 * Words];
        Gf2Poly.Multiply(a.Slice(0, Words), b.Slice(0, Words), c);
        Reduce(c, r);
    }

    internal override void Square(ReadOnlySpan<ulong> a, Span<ulong> r)
    {
        Span<ulong> c = stackalloc ulong[2 * Words];
        Gf2Poly.Square(a.Slice(0, Words), c);
        Reduce(c, r);
    }

    /// <summary>r = c mod f(t) for a polynomial c of 2 * Words words.</summary>
    private void Reduce(Span<ulong> c, Span<ulong> r)
    {
        int m = M;
        int top = m >> 6;   // word containing bit m
        int shift = m & 63;

        // Whole words above bit m: v * t^(64i) = v * t^(64i - m) * (1 + t^k [+ t^j + t^l]).
        for (int i = c.Length - 1; i > top; i--)
        {
            ulong v = c[i];
            if (v == 0)
                continue;
            c[i] = 0;
            int baseBit = 64 * i - m;
            foreach (int e in _terms)
                XorAt(c, v, baseBit + e);
        }

        // The upper part of the word that contains bit m.
        ulong rest = c[top] >> shift;
        c[top] &= shift == 0 ? 0 : (1UL << shift) - 1;
        if (rest != 0)
        {
            foreach (int e in _terms)
                XorAt(c, rest, e);
        }

        c.Slice(0, Words).CopyTo(r);
    }

    private static void XorAt(Span<ulong> c, ulong v, int bit)
    {
        int w = bit >> 6;
        int s = bit & 63;
        c[w] ^= v << s;
        if (s != 0)
            c[w + 1] ^= v >> (64 - s);
    }

    /// <summary>
    /// Checks that the reduction polynomial is irreducible. For prime m it is enough that
    /// t^(2^m) = t mod f(t) and f has no roots in GF(2) (Rabin's test); the latter holds by construction.
    /// </summary>
    public bool IsIrreducible()
    {
        if (!IsPrime(M))
            throw new NotSupportedException("The quick irreducibility test requires a prime m.");
        Span<ulong> t = stackalloc ulong[Words];
        t.Clear();
        t[0] = 2; // the polynomial t
        Span<ulong> x = stackalloc ulong[Words];
        SquareTimes(t, M, x);
        return x.SequenceEqual(t);
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

    public override bool Equals(object? obj) =>
        obj is PolynomialBasisField f && f.M == M && f.K == K && f.J == J && f.L == L;

    public override int GetHashCode() => HashCode.Combine(M, K, J, L);

    public override string ToString() => IsTrinomial
        ? $"GF(2^{M}), polynomial basis t^{M} + t^{K} + 1"
        : $"GF(2^{M}), polynomial basis t^{M} + t^{L} + t^{J} + t^{K} + 1";
}
