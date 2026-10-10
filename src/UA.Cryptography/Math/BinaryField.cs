using System.Numerics;
using System.Security.Cryptography;

namespace UA.Cryptography.Math;

public enum FieldBasis
{
    /// <summary>Polynomial basis given by a primitive trinomial or pentanomial (DSTU 4145-2002, 5.2, table 1).</summary>
    Polynomial,

    /// <summary>Gaussian optimal normal basis of type 2 (DSTU 4145-2002, В.2, table 2).</summary>
    OptimalNormal,
}

/// <summary>
/// Finite field GF(2^m).
/// </summary>
/// <remarks>
/// <para>
/// Every element has two representations:
/// <list type="bullet">
/// <item><b>standard</b> – the m-bit string of DSTU 4145-2002, 5.3 (what you see in hex in the standard,
/// in certificates and in test vectors);</item>
/// <item><b>internal</b> – whatever the implementation finds convenient. For the polynomial basis it equals
/// the standard one; for the optimal normal basis it is a permuted ("palindromic") form that turns
/// multiplication into ordinary polynomial multiplication (see <see cref="OptimalNormalBasisField"/>).</item>
/// </list>
/// Conversion happens only at the boundary (<see cref="FromBigInteger"/>, <see cref="FieldElement.ToBigInteger"/>).
/// </para>
/// <para>
/// The <c>internal</c> span-based methods work on the internal representation, never allocate on the heap
/// and allow the result span to alias the inputs. They are what the curve arithmetic uses.
/// </para>
/// </remarks>
public abstract class BinaryField
{
    private readonly Lazy<ulong[]> _traceMask;
    private FieldElement? _zero;
    private FieldElement? _one;

    protected BinaryField(int m, int words)
    {
        if (m < 2)
            throw new ArgumentOutOfRangeException(nameof(m));
        M = m;
        Words = words;
        _traceMask = new Lazy<ulong[]>(ComputeTraceMask);
    }

    /// <summary>Extension degree m.</summary>
    public int M { get; }

    public abstract FieldBasis Basis { get; }

    /// <summary>Number of 64-bit words in the internal representation.</summary>
    internal int Words { get; }

    public FieldElement Zero => _zero ??= new FieldElement(this, new ulong[Words]);

    public FieldElement One
    {
        get
        {
            if (_one is null)
            {
                var one = new ulong[Words];
                SetOne(one);
                _one = new FieldElement(this, one);
            }
            return _one;
        }
    }

    // ----------------------------------------------------------------------------------------
    // Public element construction (standard representation, DSTU 4145-2002, 5.3)
    // ----------------------------------------------------------------------------------------

    /// <summary>Creates an element from its standard representation given as a non-negative integer &lt; 2^m.</summary>
    public FieldElement FromBigInteger(BigInteger value)
    {
        if (value.Sign < 0 || value.GetBitLength() > M)
            throw new ArgumentOutOfRangeException(nameof(value), $"Field element must be a non-negative integer of at most {M} bits.");
        var std = BigIntegerToWords(value, StandardWords);
        var x = new ulong[Words];
        FromStandard(std, x);
        return new FieldElement(this, x);
    }

    /// <summary>Creates an element from its standard representation given as a hex string (spaces, '/' and line breaks are ignored).</summary>
    public FieldElement FromHex(string hex) => FromBigInteger(Hex.ToBigInteger(hex));

    /// <summary>Random element (DSTU 4145-2002, 6.4).</summary>
    public FieldElement Random(RandomNumberGenerator? rng = null)
    {
        var bytes = new byte[(M + 7) / 8];
        if (rng is null)
            RandomNumberGenerator.Fill(bytes);
        else
            rng.GetBytes(bytes);
        // The first generated bits become the most significant ones (6.4).
        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        return FromBigInteger(value >> (8 * bytes.Length - M));
    }

    internal int StandardWords => (M + 63) >> 6;

    // ----------------------------------------------------------------------------------------
    // Basis-specific primitives (internal representation)
    // ----------------------------------------------------------------------------------------

    /// <summary>r = a * b. r may alias a and/or b.</summary>
    internal abstract void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r);

    /// <summary>r = a^2. r may alias a.</summary>
    internal abstract void Square(ReadOnlySpan<ulong> a, Span<ulong> r);

    /// <summary>r = 1.</summary>
    internal abstract void SetOne(Span<ulong> r);

    /// <summary>Converts the standard representation (m-bit integer, little-endian words) to the internal one.</summary>
    internal abstract void FromStandard(ReadOnlySpan<ulong> std, Span<ulong> r);

    /// <summary>Converts the internal representation to the standard one (m-bit integer, little-endian words).</summary>
    internal abstract void ToStandard(ReadOnlySpan<ulong> a, Span<ulong> std);

    // ----------------------------------------------------------------------------------------
    // Generic algorithms
    // ----------------------------------------------------------------------------------------

    /// <summary>r = a + b. r may alias a and/or b.</summary>
    internal static void Add(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        for (int i = 0; i < r.Length; i++)
            r[i] = a[i] ^ b[i];
    }

    /// <summary>r = a^(2^k). r may alias a.</summary>
    internal void SquareTimes(ReadOnlySpan<ulong> a, int k, Span<ulong> r)
    {
        a.CopyTo(r);
        for (int i = 0; i < k; i++)
            Square(r, r);
    }

    /// <summary>
    /// r = a^-1 by the Itoh–Tsujii algorithm, x^-1 = x^(2^m - 2) (DSTU 4145-2002, В.4).
    /// Works in any basis, costs about log2(m) multiplications and m squarings.
    /// r may alias a. The inverse of zero is reported as zero.
    /// </summary>
    internal void Invert(ReadOnlySpan<ulong> a, Span<ulong> r)
    {
        int n = M - 1; // binary expansion m_r..m_0 of m - 1
        int top = 31 - BitOperations.LeadingZeroCount((uint)n);

        Span<ulong> b = stackalloc ulong[Words];
        Span<ulong> c = stackalloc ulong[Words];
        Span<ulong> x = stackalloc ulong[Words];
        a.CopyTo(x);
        a.CopyTo(b); // b = x^(2^k - 1), k = 1
        int k = 1;

        for (int i = top - 1; i >= 0; i--)
        {
            SquareTimes(b, k, c);  // c = b^(2^k)
            Multiply(b, c, b);     // b = x^(2^(2k) - 1)
            k *= 2;
            if (((n >> i) & 1) != 0)
            {
                Square(b, b);
                Multiply(b, x, b); // b = x^(2^(k+1) - 1)
                k++;
            }
        }

        Square(b, r); // x^(2^m - 2)
    }

    /// <summary>r = sqrt(a) = a^(2^(m-1)). r may alias a.</summary>
    internal void Sqrt(ReadOnlySpan<ulong> a, Span<ulong> r) => SquareTimes(a, M - 1, r);

    /// <summary>
    /// Trace tr(a) = a + a^2 + ... + a^(2^(m-1)) (DSTU 4145-2002, 6.5), returned as 0 or 1.
    /// The trace is GF(2)-linear, so it is evaluated as the parity of (a AND mask);
    /// the mask is computed once per field from the definition. The default implementation assumes
    /// the internal basis vectors are bits 0..m-1; fields with another layout override this method.
    /// </summary>
    internal virtual int Trace(ReadOnlySpan<ulong> a)
    {
        ulong[] mask = _traceMask.Value;
        ulong acc = 0;
        for (int i = 0; i < Words; i++)
            acc ^= a[i] & mask[i];
        return BitOperations.PopCount(acc) & 1;
    }

    /// <summary>Trace computed literally by the algorithm of 6.5 (used to build the mask and in tests).</summary>
    internal int TraceByDefinition(ReadOnlySpan<ulong> a)
    {
        Span<ulong> t = stackalloc ulong[Words];
        a.CopyTo(t);
        for (int i = 1; i < M; i++)
        {
            Square(t, t);
            Add(t, a, t);
        }

        // t is either 0 or 1
        if (Gf2Poly.IsZero(t))
            return 0;
        Span<ulong> one = stackalloc ulong[Words];
        SetOne(one);
        if (!t.SequenceEqual(one))
            throw new InvalidOperationException("Trace is neither 0 nor 1: the field arithmetic is broken.");
        return 1;
    }

    private ulong[] ComputeTraceMask()
    {
        var mask = new ulong[Words];
        var e = new ulong[Words];
        for (int bit = 0; bit < M; bit++)
        {
            Array.Clear(e);
            Gf2Poly.FlipBit(e, bit);
            if (TraceByDefinition(e) == 1)
                Gf2Poly.FlipBit(mask, bit);
        }
        return mask;
    }

    /// <summary>Half-trace htr(a) = sum of a^(4^i), i = 0..(m-1)/2 (DSTU 4145-2002, 6.6), m odd. r may alias a.</summary>
    internal void HalfTrace(ReadOnlySpan<ulong> a, Span<ulong> r)
    {
        if ((M & 1) == 0)
            throw new InvalidOperationException("Half-trace is defined for odd m only.");
        Span<ulong> x = stackalloc ulong[Words];
        a.CopyTo(x);
        a.CopyTo(r);
        for (int i = 1; i <= (M - 1) / 2; i++)
        {
            Square(r, r);
            Square(r, r);
            Add(r, x, r);
        }
    }

    /// <summary>
    /// Solves z^2 + u z = w (DSTU 4145-2002, 6.7). Returns the number of solutions (0, 1 or 2);
    /// when it is positive, <paramref name="z"/> receives one of them.
    /// </summary>
    internal int SolveQuadratic(ReadOnlySpan<ulong> u, ReadOnlySpan<ulong> w, Span<ulong> z)
    {
        if (Gf2Poly.IsZero(u))
        {
            Sqrt(w, z);
            return 1;
        }
        if (Gf2Poly.IsZero(w))
        {
            z.Clear();
            return 2;
        }

        Span<ulong> v = stackalloc ulong[Words];
        Span<ulong> uInv = stackalloc ulong[Words];
        Invert(u, uInv);
        Square(uInv, uInv);
        Multiply(w, uInv, v); // v = w u^-2
        if (Trace(v) == 1)
        {
            z.Clear();
            return 0;
        }
        HalfTrace(v, v);
        Multiply(v, u, z);
        return 2;
    }

    // ----------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------

    internal static ulong[] BigIntegerToWords(BigInteger value, int words)
    {
        var result = new ulong[words];
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (bytes.Length > words * 8 && !(bytes.Length == words * 8 + 1 && bytes[^1] == 0))
            throw new ArgumentOutOfRangeException(nameof(value));
        for (int i = 0; i < bytes.Length && i < words * 8; i++)
            result[i >> 3] |= (ulong)bytes[i] << (8 * (i & 7));
        return result;
    }

    internal static BigInteger WordsToBigInteger(ReadOnlySpan<ulong> words)
    {
        var bytes = new byte[words.Length * 8];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)(words[i >> 3] >> (8 * (i & 7)));
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
    }

    /// <summary>Two fields are equal when they have the same degree and the same basis.</summary>
    public abstract override bool Equals(object? obj);

    public abstract override int GetHashCode();

    public override string ToString() => $"GF(2^{M}), {Basis} basis";
}
