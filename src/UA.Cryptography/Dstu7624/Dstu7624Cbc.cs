namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (BouncyCastle's generic CBC mode as used by its DSTU 7624 tests; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>Cipher block chaining ("простої заміни з зачепленням"): whole blocks, IV of one block.</summary>
public sealed class Dstu7624Cbc
{
    private readonly Dstu7624Engine _encrypt, _decrypt;

    public Dstu7624Cbc(int blockBits, ReadOnlySpan<byte> key)
    {
        _encrypt = Dstu7624Util.Engine(blockBits, key, true);
        _decrypt = Dstu7624Util.Engine(blockBits, key, false);
    }

    public byte[] Encrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        int b = _encrypt.BlockSize;
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        if (iv.Length != b)
            throw new ArgumentException("The IV must be one block long.", nameof(iv));
        var result = data.ToArray();
        ReadOnlySpan<byte> previous = iv;
        for (int i = 0; i < result.Length; i += b)
        {
            Span<byte> block = result.AsSpan(i, b);
            Dstu7624Util.Xor(block, previous);
            _encrypt.ProcessBlock(block, block);
            previous = block;
        }
        return result;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        int b = _decrypt.BlockSize;
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        if (iv.Length != b)
            throw new ArgumentException("The IV must be one block long.", nameof(iv));
        var result = new byte[data.Length];
        ReadOnlySpan<byte> previous = iv;
        for (int i = 0; i < result.Length; i += b)
        {
            _decrypt.ProcessBlock(data.Slice(i, b), result.AsSpan(i, b));
            Dstu7624Util.Xor(result.AsSpan(i, b), previous);
            previous = data.Slice(i, b);
        }
        return result;
    }
}
