using System.Buffers.Binary;
using System.Security.Cryptography;
using UA.Cryptography.Math;

namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (KGCMBlockCipher; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Authenticated encryption GCM of DSTU 7624 (KGCMBlockCipher): counter mode of <see cref="Dstu7624Ctr"/> and a GHASH in
/// GF(2^128), GF(2^256) or GF(2^512) with little-endian words. Output of encryption: ciphertext ‖ tag. The nonce
/// (≤ one block) is right-aligned in a zero block; the tag is 64 bits to a block, multiple of 8.
/// </summary>
public sealed class Dstu7624Gcm
{
    private readonly Dstu7624Engine _engine;
    private readonly PolynomialBasisField _field;
    private readonly ulong[] _h;

    public Dstu7624Gcm(int blockBits, ReadOnlySpan<byte> key)
    {
        _engine = Dstu7624Util.Engine(blockBits, key, true);
        // x^128 + x^7 + x^2 + x + 1, x^256 + x^10 + x^5 + x^2 + 1, x^512 + x^8 + x^5 + x^2 + 1
        _field = blockBits switch
        {
            128 => new PolynomialBasisField(128, 1, 2, 7),
            256 => new PolynomialBasisField(256, 2, 5, 10),
            _ => new PolynomialBasisField(512, 2, 5, 8),
        };
        var zero = new byte[_engine.BlockSize];
        _engine.ProcessBlock(zero, zero);
        _h = ToWords(zero); // H = E(0)
    }

    public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plainText, int macBits)
    {
        int macSize = MacSize(macBits);
        var result = new byte[plainText.Length + macSize];
        Dstu7624Ctr.Process(_engine, Nonce(nonce), plainText, result);
        Tag(associatedData, result.AsSpan(0, plainText.Length)).AsSpan(0, macSize).CopyTo(result.AsSpan(plainText.Length));
        return result;
    }

    /// <summary>Verifies the tag, then decrypts; throws <see cref="CryptographicException"/> on failure.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> cipherText, int macBits)
    {
        int macSize = MacSize(macBits);
        if (cipherText.Length < macSize)
            throw new CryptographicException("The ciphertext is shorter than the tag.");
        ReadOnlySpan<byte> body = cipherText.Slice(0, cipherText.Length - macSize);
        byte[] tag = Tag(associatedData, body);
        if (!CryptographicOperations.FixedTimeEquals(tag.AsSpan(0, macSize), cipherText.Slice(body.Length)))
            throw new CryptographicException("GCM tag verification failed.");
        var plain = new byte[body.Length];
        Dstu7624Ctr.Process(_engine, Nonce(nonce), body, plain);
        return plain;
    }

    internal int MacSize(int macBits)
    {
        if (macBits < 64 || macBits > _engine.BlockSize * 8 || macBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(macBits), "The tag must be 64 bits to a block, a multiple of 8.");
        return macBits / 8;
    }

    private byte[] Nonce(ReadOnlySpan<byte> nonce) => Dstu7624Util.RightAligned(nonce, _engine.BlockSize, nameof(nonce));

    /// <summary>E(GHASH(A, C) with the bit lengths of A and C added to words 0 and n/2).</summary>
    internal byte[] Tag(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> cipherText)
    {
        var x = new ulong[_h.Length];
        Absorb(x, associatedData);
        Absorb(x, cipherText);
        x[0] ^= (ulong)(uint)associatedData.Length << 3;
        x[_h.Length / 2] ^= (ulong)(uint)cipherText.Length << 3;

        var tag = new byte[_engine.BlockSize];
        for (int i = 0; i < x.Length; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(tag.AsSpan(8 * i), x[i]);
        _engine.ProcessBlock(tag, tag);
        return tag;
    }

    /// <summary>x ← (x ⊕ block)·H for every block; a trailing partial block is zero-padded.</summary>
    private void Absorb(ulong[] x, ReadOnlySpan<byte> data)
    {
        int b = _engine.BlockSize;
        var block = new byte[b];
        for (int pos = 0; pos < data.Length; pos += b)
        {
            int len = System.Math.Min(b, data.Length - pos);
            Array.Clear(block);
            data.Slice(pos, len).CopyTo(block);
            for (int i = 0; i < x.Length; i++)
                x[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(8 * i));
            _field.Multiply(x, _h, x);
        }
    }

    private static ulong[] ToWords(byte[] bytes)
    {
        var words = new ulong[bytes.Length / 8];
        for (int i = 0; i < words.Length; i++)
            words[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(8 * i));
        return words;
    }
}
