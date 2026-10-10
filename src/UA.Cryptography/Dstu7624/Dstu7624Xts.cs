using System.Buffers.Binary;

namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (KXTSBlockCipher; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// XTS ("індексована заміна", KXTSBlockCipher): whole blocks; the tweak E(IV) is multiplied by x in GF(2^n)
/// (same polynomials as GCM) before each block. The IV must be exactly one block.
/// </summary>
public sealed class Dstu7624Xts
{
    private readonly Dstu7624Engine _tweak, _encrypt, _decrypt;
    private readonly ulong _reduction;

    public Dstu7624Xts(int blockBits, ReadOnlySpan<byte> key)
    {
        _tweak = Dstu7624Util.Engine(blockBits, key, true);
        _encrypt = _tweak;
        _decrypt = Dstu7624Util.Engine(blockBits, key, false);
        _reduction = blockBits switch { 128 => 0x87UL, 256 => 0x425UL, _ => 0x125UL };
    }

    public byte[] Encrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data) => Process(iv, data, _encrypt);

    public byte[] Decrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data) => Process(iv, data, _decrypt);

    private byte[] Process(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, Dstu7624Engine engine)
    {
        int b = engine.BlockSize;
        if (iv.Length != b)
            throw new ArgumentException("The IV must be exactly one block.", nameof(iv));
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));

        var tweakBytes = iv.ToArray();
        _tweak.ProcessBlock(tweakBytes, tweakBytes);
        var t = new ulong[b / 8];
        for (int i = 0; i < t.Length; i++)
            t[i] = BinaryPrimitives.ReadUInt64LittleEndian(tweakBytes.AsSpan(8 * i));

        var result = data.ToArray();
        for (int pos = 0; pos < result.Length; pos += b)
        {
            Double(t);
            for (int i = 0; i < t.Length; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(tweakBytes.AsSpan(8 * i), t[i]);
            Span<byte> block = result.AsSpan(pos, b);
            Dstu7624Util.Xor(block, tweakBytes);
            engine.ProcessBlock(block, block);
            Dstu7624Util.Xor(block, tweakBytes);
        }
        return result;
    }

    /// <summary>t ← t·x in GF(2^n).</summary>
    private void Double(ulong[] t)
    {
        ulong carry = 0;
        for (int i = 0; i < t.Length; i++)
        {
            ulong bit = t[i] >> 63;
            t[i] = (t[i] << 1) ^ carry;
            carry = bit;
        }
        t[0] ^= _reduction & (0UL - carry);
    }
}
