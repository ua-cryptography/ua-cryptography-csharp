using System.Numerics;
using System.Security.Cryptography;

namespace UA.Cryptography.Math;

/// <summary>Integer helpers for parameter validation.</summary>
public static class Primality
{
    /// <summary>
    /// Miller–Rabin test with 50 random bases, as in DSTU 4145-2002, 6.12.
    /// </summary>
    public static bool IsProbablePrime(BigInteger n, int rounds = 50)
    {
        if (n < 2)
            return false;
        foreach (int small in new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 })
        {
            if (n == small)
                return true;
            if (n % small == 0)
                return false;
        }

        // n - 1 = j 2^k, j odd
        BigInteger j = n - 1;
        int k = 0;
        while (j.IsEven)
        {
            j >>= 1;
            k++;
        }

        int bytes = n.GetByteCount(isUnsigned: true);
        var buffer = new byte[bytes];
        for (int i = 0; i < rounds; i++)
        {
            BigInteger a;
            do
            {
                RandomNumberGenerator.Fill(buffer);
                a = new BigInteger(buffer, isUnsigned: true) % n;
            }
            while (a < 2);

            BigInteger b = BigInteger.ModPow(a, j, n);
            if (b.IsOne || b == n - 1)
                continue;
            bool composite = true;
            for (int l = 1; l < k; l++)
            {
                b = b * b % n;
                if (b == n - 1)
                {
                    composite = false;
                    break;
                }
                if (b.IsOne)
                    return false;
            }
            if (composite)
                return false;
        }
        return true;
    }

    /// <summary>floor(sqrt(n)) for n ≥ 0.</summary>
    public static BigInteger IntegerSqrt(BigInteger n)
    {
        if (n.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(n));
        if (n < 2)
            return n;
        BigInteger x = BigInteger.One << (int)((n.GetBitLength() + 1) / 2);
        while (true)
        {
            BigInteger y = (x + n / x) >> 1;
            if (y >= x)
                return x;
            x = y;
        }
    }
}
