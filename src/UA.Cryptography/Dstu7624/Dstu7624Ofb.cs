namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (BouncyCastle's generic OFB mode as used by its DSTU 7624 tests; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Output feedback ("гамування зі зворотним зв'язком за гамою") with an s-bit segment (s = block length by default).
/// Encryption and decryption are the same operation; any message length.
/// </summary>
public sealed class Dstu7624Ofb
{
    private readonly Dstu7624Engine _engine;
    private readonly int _segment;

    public Dstu7624Ofb(int blockBits, ReadOnlySpan<byte> key, int segmentBits = 0)
    {
        _engine = Dstu7624Util.Engine(blockBits, key, true);
        segmentBits = segmentBits == 0 ? blockBits : segmentBits;
        if (segmentBits < 8 || segmentBits > blockBits || segmentBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(segmentBits));
        _segment = segmentBits / 8;
    }

    public byte[] Process(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
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
            Array.Copy(register, _segment, register, 0, b - _segment);
            Array.Copy(gamma, 0, register, b - _segment, _segment);
        }
        return result;
    }
}
