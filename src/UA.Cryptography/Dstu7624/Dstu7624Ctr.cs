namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (KCTRBlockCipher; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Counter mode of DSTU 7624 ("гамування"): the counter starts at E(IV) and is incremented as a little-endian
/// integer before each block (KCTRBlockCipher). Encryption and decryption are the same; any message length;
/// a short IV is right-aligned in a zero block.
/// </summary>
public sealed class Dstu7624Ctr
{
    private readonly Dstu7624Engine _engine;

    public Dstu7624Ctr(int blockBits, ReadOnlySpan<byte> key)
    {
        _engine = Dstu7624Util.Engine(blockBits, key, true);
    }

    public byte[] Process(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        var result = new byte[data.Length];
        Process(_engine, iv, data, result);
        return result;
    }

    internal static void Process(Dstu7624Engine engine, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, Span<byte> output)
    {
        int b = engine.BlockSize;
        byte[] counter = Dstu7624Util.RightAligned(iv, b, nameof(iv));
        engine.ProcessBlock(counter, counter); // S = E(IV)
        var gamma = new byte[b];
        for (int pos = 0; pos < data.Length; pos += b)
        {
            for (int i = 0; i < b && ++counter[i] == 0; i++)
            {
            }
            engine.ProcessBlock(counter, gamma);
            int n = System.Math.Min(b, data.Length - pos);
            for (int i = 0; i < n; i++)
                output[pos + i] = (byte)(data[pos + i] ^ gamma[i]);
        }
    }
}
