namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (BouncyCastle's generic ECB mode as used by its DSTU 7624 tests; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>Electronic codebook ("простої заміни"): whole blocks only.</summary>
public sealed class Dstu7624Ecb
{
    private readonly Dstu7624Engine _encrypt, _decrypt;

    public Dstu7624Ecb(int blockBits, ReadOnlySpan<byte> key)
    {
        _encrypt = Dstu7624Util.Engine(blockBits, key, true);
        _decrypt = Dstu7624Util.Engine(blockBits, key, false);
    }

    public byte[] Encrypt(ReadOnlySpan<byte> data) => Process(_encrypt, data);

    public byte[] Decrypt(ReadOnlySpan<byte> data) => Process(_decrypt, data);

    private static byte[] Process(Dstu7624Engine engine, ReadOnlySpan<byte> data)
    {
        int b = engine.BlockSize;
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        var result = data.ToArray();
        for (int i = 0; i < result.Length; i += b)
            engine.ProcessBlock(result.AsSpan(i, b), result.AsSpan(i, b));
        return result;
    }
}
