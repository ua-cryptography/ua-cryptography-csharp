namespace UA.Cryptography.Dstu7624;

/// <summary>Shared helpers: one cipher instance per direction, block-wise XOR.</summary>
internal static class Dstu7624Util
{
    public static Dstu7624Engine Engine(int blockBits, ReadOnlySpan<byte> key, bool forEncryption)
    {
        var engine = new Dstu7624Engine(blockBits);
        engine.Init(forEncryption, key);
        return engine;
    }

    public static void Xor(Span<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < a.Length; i++)
            a[i] ^= b[i];
    }

    /// <summary>A value shorter than the block, placed at the end of a zero block (right-aligned).</summary>
    public static byte[] RightAligned(ReadOnlySpan<byte> value, int blockSize, string name)
    {
        if (value.Length > blockSize)
            throw new ArgumentException($"{name} is longer than the block ({blockSize} bytes).", name);
        var block = new byte[blockSize];
        value.CopyTo(block.AsSpan(blockSize - value.Length));
        return block;
    }

    public static void CheckWholeBlocks(int length, int blockSize, string name)
    {
        if (length % blockSize != 0)
            throw new ArgumentException($"The length must be a multiple of the block size ({blockSize} bytes).", name);
    }
}
