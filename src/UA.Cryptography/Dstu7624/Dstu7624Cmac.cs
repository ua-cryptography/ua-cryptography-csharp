namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (DSTU7624Mac; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Message authentication code of DSTU 7624 ("вироблення імітовставки", DSTU7624Mac): a CBC-MAC whose last block is
/// masked with E(0). Input must be a non-empty whole number of blocks; the MAC length q is a multiple of 8 bits up to
/// the block length.
/// </summary>
public sealed class Dstu7624Cmac
{
    private readonly Dstu7624Engine _engine;
    private readonly int _macSize;
    private readonly byte[] _delta;

    public Dstu7624Cmac(int blockBits, ReadOnlySpan<byte> key, int macBits)
    {
        if (macBits < 8 || macBits > blockBits || macBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(macBits));
        _engine = Dstu7624Util.Engine(blockBits, key, true);
        _macSize = macBits / 8;
        _delta = new byte[_engine.BlockSize];
        _engine.ProcessBlock(_delta, _delta); // kDelta = E(0)
    }

    public byte[] ComputeMac(ReadOnlySpan<byte> data)
    {
        int b = _engine.BlockSize;
        if (data.Length == 0)
            throw new ArgumentException("The MAC is defined for a non-empty message.", nameof(data));
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        var c = new byte[b];
        for (int pos = 0; pos < data.Length; pos += b)
        {
            Dstu7624Util.Xor(c, data.Slice(pos, b));
            if (pos + b == data.Length)
                Dstu7624Util.Xor(c, _delta);
            _engine.ProcessBlock(c, c);
        }
        return c.AsSpan(0, _macSize).ToArray();
    }
}
