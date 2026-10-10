using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UA.Cryptography.Dstu7564;

/// <summary>
/// Hash function of DSTU 7564:2014 ("Kupyna"), hash sizes 256, 384 and 512 bits.
/// </summary>
/// <remarks>
/// <para>
/// The state is an 8 × c byte matrix stored as c 64-bit columns (byte r of a column is row r, little-endian):
/// c = 8 columns and 10 rounds for hashes up to 256 bits, c = 16 columns and 14 rounds for longer ones.
/// A message block M updates the state as H = T⊕(H ⊕ M) ⊕ T+(M) ⊕ H, and the result is the tail of
/// T⊕(H) ⊕ H. Both permutations use the same round: SubBytes (row r uses S-box π_(r mod 4)), ShiftBytes
/// (row r rotates by r columns; the last row by 11 in the 1024-bit state) and MixColumns (circulant MDS matrix
/// (01, 01, 05, 01, 08, 06, 07, 04) over GF(2^8) with x^8 + x^4 + x^3 + x^2 + 1); they differ in the round
/// constant: XOR in T⊕, addition mod 2^64 in T+.
/// </para>
/// <para>
/// SubBytes and MixColumns are merged into eight lookup tables built at start-up from the S-boxes, the usual
/// technique of the reference implementation (R. Oliynykov) and of BouncyCastle; the S-boxes are those of the standard
/// and are shared with DSTU 7624 (<see cref="Common.DstuSBoxes"/>).
/// </para>
/// </remarks>
public sealed class Dstu7564Hash : HashAlgorithm
{
    private const int Rows = 8;

    /// <summary>First row of the circulant MDS matrix.</summary>
    private static readonly byte[] Mds = { 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04 };

    // Tables[k][b]: the column obtained by MixColumns from a column whose only non-zero byte is π_(k mod 4)(b) in row k.
    private static readonly ulong[][] Tables = BuildTables();

    private readonly int _hashBytes;
    private readonly int _columns;
    private readonly int _rounds;
    private readonly int _blockSize;
    private readonly ulong[] _state;
    private readonly ulong[] _p;
    private readonly ulong[] _q;
    private readonly ulong[] _scratch;
    private readonly byte[] _buffer;
    private int _bufferLength;
    private ulong _length; // bytes

    /// <param name="hashSizeBits">256, 384 or 512.</param>
    public Dstu7564Hash(int hashSizeBits = 256)
    {
        if (hashSizeBits is not (256 or 384 or 512))
            throw new ArgumentOutOfRangeException(nameof(hashSizeBits), "Supported hash sizes are 256, 384 and 512 bits.");
        _hashBytes = hashSizeBits / 8;
        _columns = hashSizeBits <= 256 ? 8 : 16;
        _rounds = hashSizeBits <= 256 ? 10 : 14;
        _blockSize = 8 * _columns;
        _state = new ulong[_columns];
        _p = new ulong[_columns];
        _q = new ulong[_columns];
        _scratch = new ulong[_columns];
        _buffer = new byte[_blockSize];
        HashSizeValue = hashSizeBits;
        Initialize();
    }

    /// <summary>One-shot hash.</summary>
    public static byte[] HashData(ReadOnlySpan<byte> data, int hashSizeBits = 256)
    {
        using var h = new Dstu7564Hash(hashSizeBits);
        return h.ComputeHash(data.ToArray());
    }

    public override void Initialize()
    {
        Array.Clear(_state);
        _state[0] = (ulong)_blockSize; // initial value: the block length in bytes in the first byte
        _bufferLength = 0;
        _length = 0;
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize) => HashCore(array.AsSpan(ibStart, cbSize));

    protected override void HashCore(ReadOnlySpan<byte> source)
    {
        _length += (ulong)source.Length;
        while (source.Length > 0)
        {
            int n = System.Math.Min(_blockSize - _bufferLength, source.Length);
            source.Slice(0, n).CopyTo(_buffer.AsSpan(_bufferLength));
            _bufferLength += n;
            source = source.Slice(n);
            if (_bufferLength == _blockSize)
            {
                ProcessBlock(_buffer);
                _bufferLength = 0;
            }
        }
    }

    protected override byte[] HashFinal()
    {
        // Padding: a single 1 bit (0x80), zeros, and the message length in bits as a 96-bit little-endian number.
        _buffer[_bufferLength++] = 0x80;
        if (_bufferLength > _blockSize - 12)
        {
            Array.Clear(_buffer, _bufferLength, _blockSize - _bufferLength);
            ProcessBlock(_buffer);
            _bufferLength = 0;
        }
        Array.Clear(_buffer, _bufferLength, _blockSize - _bufferLength);
        Span<byte> length = _buffer.AsSpan(_blockSize - 12);
        BinaryPrimitives.WriteUInt64LittleEndian(length, _length << 3);
        BinaryPrimitives.WriteUInt32LittleEndian(length.Slice(8), (uint)(_length >> 61));
        ProcessBlock(_buffer);

        // H = T⊕(H) ⊕ H; the hash is its last n bits.
        _state.CopyTo(_p, 0);
        PermutationXor(_p);
        for (int c = 0; c < _columns; c++)
            _state[c] ^= _p[c];

        var result = new byte[_hashBytes];
        int first = _columns - _hashBytes / 8;
        for (int c = first; c < _columns; c++)
            BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(8 * (c - first)), _state[c]);
        return result;
    }

    private void ProcessBlock(ReadOnlySpan<byte> block)
    {
        for (int c = 0; c < _columns; c++)
        {
            ulong m = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(8 * c));
            _p[c] = _state[c] ^ m;
            _q[c] = m;
        }
        PermutationXor(_p);
        PermutationAdd(_q);
        for (int c = 0; c < _columns; c++)
            _state[c] ^= _p[c] ^ _q[c];
    }

    /// <summary>T⊕: the round constant of column j, (j &lt;&lt; 4) ⊕ round, is XORed into row 0.</summary>
    private void PermutationXor(ulong[] s)
    {
        for (int round = 0; round < _rounds; round++)
        {
            for (int c = 0; c < _columns; c++)
                s[c] ^= (ulong)((c << 4) ^ round);
            Round(s);
        }
    }

    /// <summary>
    /// T+: the column j is increased mod 2^64 by 00F0F0F0F0F0F0F3 with ((c − 1 − j) &lt;&lt; 4) ⊕ round in row 7.
    /// </summary>
    private void PermutationAdd(ulong[] s)
    {
        for (int round = 0; round < _rounds; round++)
        {
            for (int c = 0; c < _columns; c++)
                s[c] += 0x00F0F0F0F0F0F0F3UL ^ ((ulong)(((_columns - 1 - c) << 4) ^ round) << 56);
            Round(s);
        }
    }

    /// <summary>SubBytes, ShiftBytes and MixColumns: output row r of column c comes from column c − shift(r).</summary>
    private void Round(ulong[] s)
    {
        ulong[] t = _scratch;
        Array.Copy(s, t, _columns);
        int mask = _columns - 1;
        int lastShift = _columns == 8 ? 7 : 11;
        for (int c = 0; c < _columns; c++)
        {
            ulong v = 0;
            for (int r = 0; r < Rows; r++)
            {
                int source = (c - (r == Rows - 1 ? lastShift : r)) & mask;
                v ^= Tables[r][(int)(t[source] >> (8 * r)) & 0xFF];
            }
            s[c] = v;
        }
    }

    private static ulong[][] BuildTables()
    {
        var tables = new ulong[Rows][];
        for (int k = 0; k < Rows; k++)
        {
            tables[k] = new ulong[256];
            for (int b = 0; b < 256; b++)
            {
                byte y = Common.DstuSBoxes.Pi[k % 4][b];
                ulong column = 0;
                for (int i = 0; i < Rows; i++) // row i of the product: M[i][k] · y, M[i][k] = Mds[(k − i) mod 8]
                    column |= (ulong)GfMultiply(Mds[(k - i) & 7], y) << (8 * i);
                tables[k][b] = column;
            }
        }
        return tables;
    }

    /// <summary>Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.</summary>
    private static byte GfMultiply(byte a, byte b)
    {
        int result = 0, x = a, y = b;
        while (y != 0)
        {
            if ((y & 1) != 0)
                result ^= x;
            x <<= 1;
            if ((x & 0x100) != 0)
                x ^= 0x11D;
            y >>= 1;
        }
        return (byte)result;
    }
}
