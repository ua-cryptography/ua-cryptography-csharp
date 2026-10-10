using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using ArmAes = System.Runtime.Intrinsics.Arm.Aes;
using ArmBase = System.Runtime.Intrinsics.Arm.ArmBase;
using X86Pclmul = System.Runtime.Intrinsics.X86.Pclmulqdq;

namespace UA.Cryptography.Math;

/// <summary>
/// Low-level arithmetic on binary polynomials (elements of GF(2)[x]) stored as little-endian
/// arrays of 64-bit words: coefficient of x^i is bit (i % 64) of word (i / 64).
/// </summary>
/// <remarks>
/// This is the only place that depends on the CPU: carry-less multiplication uses PMULL (ARMv8 Crypto)
/// or PCLMULQDQ (x86) when available and falls back to a portable 4-bit window method otherwise.
/// Everything above this layer is plain word arithmetic and ports directly to other languages.
/// </remarks>
internal static class Gf2Poly
{
    /// <summary>Hardware carry-less multiplication is available on this CPU.</summary>
    public static readonly bool HardwareSupported = ArmAes.IsSupported || X86Pclmul.IsSupported;

    /// <summary>Allows tests and benchmarks to force the portable implementation.</summary>
    public static bool UseHardware { get; set; } = HardwareSupported;

    /// <summary>
    /// r = a * b in GF(2)[x]. <paramref name="r"/> must hold a.Length + b.Length words
    /// and must not overlap the inputs.
    /// </summary>
    public static void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        r = r.Slice(0, a.Length + b.Length);
        if (UseHardware && HardwareSupported)
        {
            MultiplyHardware(a, b, r);
        }
        else
        {
            r.Clear();
            MultiplySoftware(a, b, r);
        }
    }

    /// <summary>
    /// Hardware path of <see cref="Multiply"/>. Product scanning: output word k collects lo(a_i b_j) for i + j = k
    /// and hi(a_i b_j) for i + j = k - 1, so the partial products stay in registers and r is written once.
    /// </summary>
    internal static void MultiplyHardware(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        int na = a.Length, nb = b.Length;
        if (r.Length < na + nb)
            throw new ArgumentException("Result is too short.", nameof(r));
        if (na == 0 || nb == 0)
        {
            r.Slice(0, na + nb).Clear();
            return;
        }

        ref ulong ra = ref MemoryMarshal.GetReference(a);
        ref ulong rb = ref MemoryMarshal.GetReference(b);
        ref ulong rr = ref MemoryMarshal.GetReference(r);
        ulong prevHi = 0;
        for (int k = 0; k < na + nb - 1; k++)
        {
            int iFrom = System.Math.Max(0, k - nb + 1);
            int iTo = System.Math.Min(k, na - 1);
            Vector128<ulong> acc = Vector128<ulong>.Zero;
            for (int i = iFrom; i <= iTo; i++)
                acc ^= ClMul(Unsafe.Add(ref ra, i), Unsafe.Add(ref rb, k - i));
            Unsafe.Add(ref rr, k) = acc.GetElement(0) ^ prevHi;
            prevHi = acc.GetElement(1);
        }
        Unsafe.Add(ref rr, na + nb - 1) = prevHi;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> ClMul(ulong x, ulong y)
    {
        if (ArmAes.IsSupported)
            return ArmAes.PolynomialMultiplyWideningLower(Vector64.CreateScalar(x), Vector64.CreateScalar(y));
        if (X86Pclmul.IsSupported)
            return X86Pclmul.CarrylessMultiply(Vector128.CreateScalar(x), Vector128.CreateScalar(y), 0x00);
        throw new PlatformNotSupportedException("No carry-less multiplication instruction on this CPU.");
    }

    /// <summary>Portable path of <see cref="Multiply"/>; r must be cleared by the caller.</summary>
    internal static void MultiplySoftware(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        Span<ulong> table = stackalloc ulong[16];
        for (int j = 0; j < b.Length; j++)
        {
            ulong bj = b[j];
            BuildWindowTable(bj, table);
            for (int i = 0; i < a.Length; i++)
            {
                ulong hi = Multiply64(a[i], bj, table, out ulong lo);
                r[i + j] ^= lo;
                r[i + j + 1] ^= hi;
            }
        }
    }

    /// <summary>table[k] = k * b mod x^64 for k = 0..15.</summary>
    private static void BuildWindowTable(ulong b, Span<ulong> table)
    {
        table[0] = 0;
        table[1] = b;
        for (int k = 2; k < 16; k += 2)
        {
            table[k] = table[k >> 1] << 1;
            table[k + 1] = table[k] ^ b;
        }
    }

    /// <summary>Portable 64x64 -> 128 bit carry-less multiplication (4-bit window).</summary>
    private static ulong Multiply64(ulong a, ulong b, ReadOnlySpan<ulong> table, out ulong lo)
    {
        ulong l = table[(int)(a >> 60)];
        ulong h = 0;
        for (int s = 56; s >= 0; s -= 4)
        {
            h = (h << 4) | (l >> 60);
            l = (l << 4) ^ table[(int)((a >> s) & 0xF)];
        }

        // The table entries lost the top bits of b shifted out by the window (k * b overflows 64 bits).
        h ^= ((a & 0xEEEEEEEEEEEEEEEEUL) >> 1) & (0UL - (b >> 63));
        h ^= ((a & 0xCCCCCCCCCCCCCCCCUL) >> 2) & (0UL - ((b >> 62) & 1));
        h ^= ((a & 0x8888888888888888UL) >> 3) & (0UL - ((b >> 61) & 1));

        lo = l;
        return h;
    }

    /// <summary>Single-word carry-less product, used by tests as a reference point.</summary>
    public static ulong Multiply64(ulong a, ulong b, out ulong lo)
    {
        Span<ulong> table = stackalloc ulong[16];
        BuildWindowTable(b, table);
        return Multiply64(a, b, table, out lo);
    }

    /// <summary>r = a^2 in GF(2)[x] (bit i moves to bit 2i). r must hold 2 * a.Length words.</summary>
    public static void Square(ReadOnlySpan<ulong> a, Span<ulong> r)
    {
        for (int i = a.Length - 1; i >= 0; i--)
        {
            ulong w = a[i];
            r[2 * i + 1] = Spread32(w >> 32);
            r[2 * i] = Spread32(w & 0xFFFFFFFFUL);
        }
    }

    /// <summary>Inserts a zero bit after every bit of the low 32 bits of x.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Spread32(ulong x)
    {
        x = (x | (x << 16)) & 0x0000FFFF0000FFFFUL;
        x = (x | (x << 8)) & 0x00FF00FF00FF00FFUL;
        x = (x | (x << 4)) & 0x0F0F0F0F0F0F0F0FUL;
        x = (x | (x << 2)) & 0x3333333333333333UL;
        x = (x | (x << 1)) & 0x5555555555555555UL;
        return x;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ReverseBits(ulong x)
    {
        if (ArmBase.Arm64.IsSupported)
            return ArmBase.Arm64.ReverseElementBits(x);
        return ReverseBitsPortable(x);
    }

    internal static ulong ReverseBitsPortable(ulong x)
    {
        x = BinaryPrimitives.ReverseEndianness(x);
        x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FUL) | ((x & 0x0F0F0F0F0F0F0F0FUL) << 4);
        x = ((x >> 2) & 0x3333333333333333UL) | ((x & 0x3333333333333333UL) << 2);
        x = ((x >> 1) & 0x5555555555555555UL) | ((x & 0x5555555555555555UL) << 1);
        return x;
    }

    /// <summary>
    /// dst = src >> shift (bits shifted below zero are dropped, bits that do not fit into dst are dropped).
    /// dst and src may be the same span.
    /// </summary>
    public static void ShiftRight(ReadOnlySpan<ulong> src, int shift, Span<ulong> dst)
    {
        int words = shift >> 6;
        int bits = shift & 63;
        for (int i = 0; i < dst.Length; i++)
        {
            int k = i + words;
            ulong lo = k < src.Length ? src[k] : 0;
            if (bits != 0)
            {
                ulong hi = k + 1 < src.Length ? src[k + 1] : 0;
                lo = (lo >> bits) | (hi << (64 - bits));
            }
            dst[i] = lo;
        }
    }

    /// <summary>dst = src &lt;&lt; shift, truncated to dst.Length words. dst and src may be the same span.</summary>
    public static void ShiftLeft(ReadOnlySpan<ulong> src, int shift, Span<ulong> dst)
    {
        int words = shift >> 6;
        int bits = shift & 63;
        for (int i = dst.Length - 1; i >= 0; i--)
        {
            int k = i - words;
            ulong hi = k >= 0 && k < src.Length ? src[k] : 0;
            if (bits != 0)
            {
                ulong lo = k - 1 >= 0 && k - 1 < src.Length ? src[k - 1] : 0;
                hi = (hi << bits) | (lo >> (64 - bits));
            }
            dst[i] = hi;
        }
    }

    /// <summary>
    /// Reverses the order of the lowest <c>64 * src.Length</c> bits: dst bit (64n - 1 - u) = src bit u.
    /// dst must hold src.Length words and must not overlap src.
    /// </summary>
    public static void ReverseWords(ReadOnlySpan<ulong> src, Span<ulong> dst)
    {
        int n = src.Length;
        for (int i = 0; i < n; i++)
            dst[i] = ReverseBits(src[n - 1 - i]);
    }

    /// <summary>Clears all bits at positions &gt;= bitCount.</summary>
    public static void ClearAbove(Span<ulong> a, int bitCount)
    {
        int word = bitCount >> 6;
        int bits = bitCount & 63;
        if (word >= a.Length)
            return;
        if (bits != 0)
        {
            a[word] &= (1UL << bits) - 1;
            word++;
        }
        a.Slice(word).Clear();
    }

    public static void Xor(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        for (int i = 0; i < a.Length; i++)
            a[i] ^= b[i];
    }

    public static bool IsZero(ReadOnlySpan<ulong> a)
    {
        ulong acc = 0;
        foreach (ulong w in a)
            acc |= w;
        return acc == 0;
    }

    public static int Degree(ReadOnlySpan<ulong> a)
    {
        for (int i = a.Length - 1; i >= 0; i--)
        {
            if (a[i] != 0)
                return i * 64 + 63 - System.Numerics.BitOperations.LeadingZeroCount(a[i]);
        }
        return -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TestBit(ReadOnlySpan<ulong> a, int bit) => ((a[bit >> 6] >> (bit & 63)) & 1) != 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void FlipBit(Span<ulong> a, int bit) => a[bit >> 6] ^= 1UL << (bit & 63);

    /// <summary>Parity (sum mod 2) of all bits.</summary>
    public static int Parity(ReadOnlySpan<ulong> a)
    {
        ulong acc = 0;
        foreach (ulong w in a)
            acc ^= w;
        return System.Numerics.BitOperations.PopCount(acc) & 1;
    }
}
