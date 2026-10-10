using System.Buffers.Binary;
using System.Numerics;

namespace UA.Cryptography.Gost;

/// <summary>
/// GOST 28147-89 block cipher, simple substitution (ECB) mode on single 64-bit blocks.
/// Used here as the compression primitive of GOST 34.311-95; DSTU 4145-2002 also builds its random bit generator
/// (Appendix A) on it.
/// </summary>
/// <remarks>
/// The substitution table is 8 S-boxes of 16 four-bit entries, given as 128 bytes: entry v of S-box j is
/// <c>sbox[16 j + v]</c>, and S-box j substitutes bits 4j..4j+3 of the 32-bit round value. Ukrainian PKI carries the
/// table in "DKE" form, 64 bytes with two entries per byte; see <see cref="ExpandDke"/>.
/// </remarks>
public sealed class Gost28147
{
    private readonly uint[] _table = new uint[4 * 256]; // S-boxes merged by bytes and pre-rotated by 11 bits
    private readonly uint[] _key = new uint[8];

    public Gost28147(ReadOnlySpan<byte> sbox)
    {
        if (sbox.Length != 128)
            throw new ArgumentException("A GOST 28147 substitution table has 128 entries.", nameof(sbox));
        for (int i = 0; i < 128; i++)
        {
            if (sbox[i] > 15)
                throw new ArgumentException("S-box entries must be 4-bit values.", nameof(sbox));
        }

        // f(x) = rotl11(S(x)); since S works nibble-wise, it is a sum of four byte-indexed tables.
        for (int b = 0; b < 4; b++)
        {
            for (int v = 0; v < 256; v++)
            {
                uint lo = sbox[16 * (2 * b) + (v & 15)];
                uint hi = sbox[16 * (2 * b + 1) + (v >> 4)];
                uint s = (lo | (hi << 4)) << (8 * b);
                _table[256 * b + v] = BitOperations.RotateLeft(s, 11);
            }
        }
    }

    /// <summary>
    /// Expands a 64-byte DKE (two S-box entries per byte, high nibble first) into the 128-entry table.
    /// </summary>
    public static byte[] ExpandDke(ReadOnlySpan<byte> dke)
    {
        if (dke.Length != 64)
            throw new ArgumentException("DKE must be 64 bytes long.", nameof(dke));
        var sbox = new byte[128];
        for (int i = 0; i < 64; i++)
        {
            sbox[2 * i] = (byte)(dke[i] >> 4);
            sbox[2 * i + 1] = (byte)(dke[i] & 0x0F);
        }
        return sbox;
    }

    /// <summary>Sets the 256-bit key: eight 32-bit little-endian subkeys K0..K7.</summary>
    public void SetKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("GOST 28147 key must be 32 bytes long.", nameof(key));
        for (int i = 0; i < 8; i++)
            _key[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4 * i));
    }

    /// <summary>Encrypts one 8-byte block (N1 = first four bytes, N2 = last four, little-endian).</summary>
    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(input);
        uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4));

        // Subkeys K0..K7 three times, then K7..K0; no swap after the last round.
        for (int k = 0; k < 3; k++)
        {
            for (int j = 0; j < 8; j++)
                (n1, n2) = (n2 ^ F(n1 + _key[j]), n1);
        }
        for (int j = 7; j > 0; j--)
            (n1, n2) = (n2 ^ F(n1 + _key[j]), n1);
        n2 ^= F(n1 + _key[0]);

        BinaryPrimitives.WriteUInt32LittleEndian(output, n1);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4), n2);
    }

    /// <summary>Decrypts one 8-byte block.</summary>
    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(input);
        uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4));

        // Subkeys K0..K7 once, then K7..K0 three times; no swap after the last round.
        for (int j = 0; j < 8; j++)
            (n1, n2) = (n2 ^ F(n1 + _key[j]), n1);
        for (int k = 0; k < 3; k++)
        {
            for (int j = 7; j >= 0; j--)
            {
                if (k == 2 && j == 0)
                    break;
                (n1, n2) = (n2 ^ F(n1 + _key[j]), n1);
            }
        }
        n2 ^= F(n1 + _key[0]);

        BinaryPrimitives.WriteUInt32LittleEndian(output, n1);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4), n2);
    }

    private uint F(uint x) =>
        _table[x & 0xFF] ^ _table[256 + ((x >> 8) & 0xFF)] ^ _table[512 + ((x >> 16) & 0xFF)] ^ _table[768 + (x >> 24)];
}
