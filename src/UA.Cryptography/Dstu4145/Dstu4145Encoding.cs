using System.Numerics;
using UA.Cryptography.Math;

namespace UA.Cryptography.Dstu4145;

/// <summary>Data conversions of DSTU 4145-2002, section 5.</summary>
public static class Dstu4145Encoding
{
    /// <summary>
    /// 5.8: field element → integer. Takes the L(n) − 1 least significant bits of the standard representation,
    /// so the result is always &lt; n.
    /// </summary>
    public static BigInteger FieldElementToInteger(FieldElement x, BigInteger n)
    {
        int k = BitLength(n) - 1;
        return x.ToBigInteger() & ((BigInteger.One << k) - 1);
    }

    /// <summary>
    /// 5.9: hash code → field element. The hash is the binary string (h_{L_H−1}, ..., h_0) given as bytes in
    /// big-endian order (the first byte holds the most significant bits, exactly as the hex strings in Appendix Б);
    /// its min(m, L_H) least significant bits become the element.
    /// </summary>
    /// <remarks>
    /// GOST 34.311 implementations usually output the digest as a little-endian byte array; reverse it first
    /// if your hash function produces bytes in that order.
    /// </remarks>
    public static FieldElement HashToFieldElement(ReadOnlySpan<byte> hash, BinaryField field)
    {
        var h = new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        h &= (BigInteger.One << field.M) - 1;
        return field.FromBigInteger(h);
    }

    /// <summary>
    /// 5.10: (r, s) → signature D = S ‖ R of <paramref name="signatureBits"/> bits, returned as big-endian bytes
    /// (s occupies the most significant half).
    /// </summary>
    public static byte[] EncodeSignature(BigInteger r, BigInteger s, int signatureBits)
    {
        if (signatureBits <= 0 || signatureBits % 16 != 0)
            throw new ArgumentException("The signature length L_D must be a positive multiple of 16.", nameof(signatureBits));
        int half = signatureBits / 2;
        if (r.Sign <= 0 || s.Sign <= 0 || BitLength(r) > half || BitLength(s) > half)
            throw new ArgumentException("r and s must be positive and fit into L_D / 2 bits.");

        BigInteger d = (s << half) | r;
        var result = new byte[signatureBits / 8];
        byte[] bytes = d.ToByteArray(isUnsigned: true, isBigEndian: true);
        bytes.CopyTo(result, result.Length - bytes.Length);
        return result;
    }

    /// <summary>5.11: signature D (big-endian bytes, even bit length) → (r, s).</summary>
    public static (BigInteger R, BigInteger S) DecodeSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length == 0)
            throw new ArgumentException("Empty signature.", nameof(signature));
        int half = signature.Length * 8 / 2;
        var d = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
        BigInteger mask = (BigInteger.One << half) - 1;
        return (d & mask, d >> half);
    }

    /// <summary>L(a) of 5.1: length of the binary representation; L(0) = 1.</summary>
    public static int BitLength(BigInteger a) => a.IsZero ? 1 : (int)a.GetBitLength();
}
