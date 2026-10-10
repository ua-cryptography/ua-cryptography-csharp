using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (DSTU7624WrapEngine; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>Key wrapping ("захист ключів", DSTU7624WrapEngine): whole blocks; the wrapped value is one block longer.</summary>
public sealed class Dstu7624KeyWrap
{
    private readonly Dstu7624Engine _encrypt, _decrypt;

    public Dstu7624KeyWrap(int blockBits, ReadOnlySpan<byte> key)
    {
        _encrypt = Dstu7624Util.Engine(blockBits, key, true);
        _decrypt = Dstu7624Util.Engine(blockBits, key, false);
    }

    public byte[] Wrap(ReadOnlySpan<byte> data)
    {
        int b = _encrypt.BlockSize, half = b / 2;
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        if (data.Length == 0)
            throw new ArgumentException("Nothing to wrap.", nameof(data));

        int n = 2 * (1 + data.Length / b);
        int v = (n - 1) * 6;
        var buffer = new byte[data.Length + b]; // data followed by a zero block (the integrity check)
        data.CopyTo(buffer);

        var bHalf = buffer.AsSpan(0, half).ToArray();
        var halves = new List<byte[]>();
        for (int off = half; off < buffer.Length; off += half)
            halves.Add(buffer.AsSpan(off, half).ToArray());

        var block = new byte[b];
        for (int j = 0; j < v; j++)
        {
            bHalf.CopyTo(block, 0);
            halves[0].CopyTo(block, half);
            _encrypt.ProcessBlock(block, block);
            XorCounter(block.AsSpan(half), j + 1);
            Array.Copy(block, half, bHalf, 0, half);
            for (int i = 2; i < n; i++)
                halves[i - 1].CopyTo(halves[i - 2], 0);
            Array.Copy(block, 0, halves[n - 2], 0, half);
        }

        bHalf.CopyTo(buffer, 0);
        for (int i = 0; i < n - 1; i++)
            halves[i].CopyTo(buffer, half + i * half);
        return buffer;
    }

    /// <summary>Unwraps and checks integrity; throws <see cref="CryptographicException"/> on failure.</summary>
    public byte[] Unwrap(ReadOnlySpan<byte> data)
    {
        int b = _decrypt.BlockSize, half = b / 2;
        Dstu7624Util.CheckWholeBlocks(data.Length, b, nameof(data));
        if (data.Length < 2 * b)
            throw new CryptographicException("The wrapped data is too short.");

        int n = 2 * data.Length / b;
        int v = (n - 1) * 6;
        var buffer = data.ToArray();
        var bHalf = buffer.AsSpan(0, half).ToArray();
        var halves = new List<byte[]>();
        for (int off = half; off < buffer.Length; off += half)
            halves.Add(buffer.AsSpan(off, half).ToArray());

        var block = new byte[b];
        for (int j = 0; j < v; j++)
        {
            halves[n - 2].CopyTo(block, 0);
            bHalf.CopyTo(block, half);
            XorCounter(block.AsSpan(half), v - j);
            _decrypt.ProcessBlock(block, block);
            Array.Copy(block, 0, bHalf, 0, half);
            for (int i = 2; i < n; i++)
                halves[n - i - 1].CopyTo(halves[n - i], 0);
            Array.Copy(block, half, halves[0], 0, half);
        }

        bHalf.CopyTo(buffer, 0);
        for (int i = 0; i < n - 1; i++)
            halves[i].CopyTo(buffer, half + i * half);

        if (!CryptographicOperations.FixedTimeEquals(buffer.AsSpan(buffer.Length - b), new byte[b]))
            throw new CryptographicException("Key unwrap integrity check failed.");
        return buffer.AsSpan(0, buffer.Length - b).ToArray();
    }

    private static void XorCounter(Span<byte> target, int counter)
    {
        Span<byte> c = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(c, counter);
        for (int i = 0; i < 4; i++)
            target[i] ^= c[i];
    }
}
