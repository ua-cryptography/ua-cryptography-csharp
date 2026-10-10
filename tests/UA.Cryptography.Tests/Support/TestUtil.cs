using System.Numerics;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Support;

internal static class TestUtil
{
    /// <summary>Deterministic pseudo-random non-negative integer of at most <paramref name="bits"/> bits.</summary>
    public static BigInteger RandomInteger(Random random, int bits)
    {
        var bytes = new byte[(bits + 7) / 8 + 1];
        random.NextBytes(bytes);
        bytes[^1] = 0;
        var value = new BigInteger(bytes);
        return value & ((BigInteger.One << bits) - 1);
    }

    public static FieldElement RandomElement(BinaryField field, Random random) =>
        field.FromBigInteger(RandomInteger(random, field.M));

    public static ulong[] RandomWords(Random random, int words)
    {
        var a = new ulong[words];
        for (int i = 0; i < words; i++)
            a[i] = (ulong)random.NextInt64() ^ ((ulong)random.Next() << 40);
        return a;
    }

    /// <summary>Schoolbook bit-by-bit product in GF(2)[x], the slowest and most obvious reference.</summary>
    public static ulong[] NaiveMultiply(ulong[] a, ulong[] b)
    {
        var r = new ulong[a.Length + b.Length];
        for (int i = 0; i < a.Length * 64; i++)
        {
            if (((a[i >> 6] >> (i & 63)) & 1) == 0)
                continue;
            for (int j = 0; j < b.Length * 64; j++)
            {
                if (((b[j >> 6] >> (j & 63)) & 1) != 0)
                    r[(i + j) >> 6] ^= 1UL << ((i + j) & 63);
            }
        }
        return r;
    }
}
