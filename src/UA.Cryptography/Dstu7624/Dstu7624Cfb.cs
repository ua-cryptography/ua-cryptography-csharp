namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (BouncyCastle's generic CFB mode as used by its DSTU 7624 tests; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Cipher feedback ("гамування зі зворотним зв'язком за шифрограмою") with an s-bit segment (8 ≤ s ≤ block, multiple
/// of 8; s = block length by default). Any message length; a short IV is right-aligned in a zero block.
/// </summary>
public sealed class Dstu7624Cfb
{
    private readonly Dstu7624Engine _engine;
    private readonly int _segment;

    public Dstu7624Cfb(int blockBits, ReadOnlySpan<byte> key, int segmentBits = 0)
    {
        _engine = Dstu7624Util.Engine(blockBits, key, true);
        segmentBits = segmentBits == 0 ? blockBits : segmentBits;
        if (segmentBits < 8 || segmentBits > blockBits || segmentBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(segmentBits));
        _segment = segmentBits / 8;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data) => Process(iv, data, encrypt: true);

    public byte[] Decrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data) => Process(iv, data, encrypt: false);

    private byte[] Process(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, bool encrypt)
    {
        int b = _engine.BlockSize;
        byte[] register = Dstu7624Util.RightAligned(iv, b, nameof(iv));
        var gamma = new byte[b];
        var result = new byte[data.Length];
        for (int pos = 0; pos < data.Length; pos += _segment)
        {
            int n = System.Math.Min(_segment, data.Length - pos);
            _engine.ProcessBlock(register, gamma);
            for (int i = 0; i < n; i++)
                result[pos + i] = (byte)(data[pos + i] ^ gamma[i]);
            // the register shifts left by one segment and takes in the ciphertext
            ReadOnlySpan<byte> cipherText = encrypt ? result.AsSpan(pos, n) : data.Slice(pos, n);
            Array.Copy(register, _segment, register, 0, b - _segment);
            cipherText.CopyTo(register.AsSpan(b - _segment));
        }
        return result;
    }
}
