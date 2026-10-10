using System.Buffers.Binary;
using UA.Cryptography.Common;

namespace UA.Cryptography.Dstu7624;

/// <summary>
/// Block cipher of DSTU 7624:2014 ("Kalyna"): 128-, 256- or 512-bit blocks with a key of the block size or of twice
/// the block size (128/128, 128/256, 256/256, 256/512, 512/512).
/// </summary>
/// <remarks>
/// Translated to C# from BouncyCastle Java 1.86 (<c>org.bouncycastle.crypto.engines.DSTU7624Engine</c>, MIT licence,
/// see THIRD-PARTY-NOTICES.md), itself based on R. Oliynykov's reference implementation. The state is a column-major
/// 8 × c byte matrix stored as c 64-bit little-endian columns, exactly like in DSTU 7564; the S-boxes are shared with it.
/// </remarks>
public sealed class Dstu7624Engine
{
    private readonly int _wordsInBlock;
    private ulong[] _state;
    private ulong[][]? _roundKeys;
    private int _wordsInKey;
    private int _rounds;
    private bool _forEncryption;

    /// <param name="blockBits">128, 256 or 512.</param>
    public Dstu7624Engine(int blockBits)
    {
        if (blockBits is not (128 or 256 or 512))
            throw new ArgumentOutOfRangeException(nameof(blockBits), "Block length must be 128, 256 or 512 bits.");
        _wordsInBlock = blockBits >> 6;
        _state = new ulong[_wordsInBlock];
    }

    /// <summary>Block size in bytes.</summary>
    public int BlockSize => _wordsInBlock << 3;

    /// <summary>Expands the key (table 6.1 of the standard: key length equal to or twice the block length).</summary>
    public void Init(bool forEncryption, ReadOnlySpan<byte> key)
    {
        int keyBits = key.Length * 8;
        int blockBits = _wordsInBlock << 6;
        if (keyBits is not (128 or 256 or 512) || (keyBits != blockBits && keyBits != 2 * blockBits))
            throw new ArgumentException($"A {blockBits}-bit block needs a {blockBits}- or {2 * blockBits}-bit key.", nameof(key));

        _forEncryption = forEncryption;
        _rounds = keyBits switch { 128 => 10, 256 => 14, _ => 18 };
        _wordsInKey = keyBits >> 6;
        _roundKeys = new ulong[_rounds + 1][];
        for (int i = 0; i <= _rounds; i++)
            _roundKeys[i] = new ulong[_wordsInBlock];

        var workingKey = new ulong[_wordsInKey];
        for (int i = 0; i < _wordsInKey; i++)
            workingKey[i] = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(8 * i));

        var tempKeys = new ulong[_wordsInBlock];
        WorkingKeyExpandKt(workingKey, tempKeys);
        WorkingKeyExpandEven(workingKey, tempKeys);
        WorkingKeyExpandOdd();
    }

    /// <summary>Encrypts or decrypts one block. Input and output may be the same span.</summary>
    public void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (_roundKeys is null)
            throw new InvalidOperationException("The cipher is not initialised.");
        int size = BlockSize;
        if (input.Length < size || output.Length < size)
            throw new ArgumentException("Buffers must hold a whole block.");

        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(8 * i));

        if (_forEncryption)
        {
            AddRoundKey(0);
            for (int round = 0; ;)
            {
                SubBytes();
                ShiftRows();
                MixColumns();
                if (++round == _rounds)
                    break;
                XorRoundKey(round);
            }
            AddRoundKey(_rounds);
        }
        else
        {
            SubRoundKey(_rounds);
            for (int round = _rounds; ;)
            {
                MixColumnsInv();
                InvShiftRows();
                InvSubBytes();
                if (--round == 0)
                    break;
                XorRoundKey(round);
            }
            SubRoundKey(0);
        }

        for (int i = 0; i < _wordsInBlock; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(output.Slice(8 * i), _state[i]);
    }

    // ---------------------------------------------------------------------------------------------
    // Round keys
    // ---------------------------------------------------------------------------------------------

    private void AddRoundKey(int round)
    {
        ulong[] k = _roundKeys![round];
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] += k[i];
    }

    private void SubRoundKey(int round)
    {
        ulong[] k = _roundKeys![round];
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] -= k[i];
    }

    private void XorRoundKey(int round)
    {
        ulong[] k = _roundKeys![round];
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] ^= k[i];
    }

    /// <summary>The intermediate key K_t (KSA of the standard, strengthened against the AES related-key weaknesses).</summary>
    private void WorkingKeyExpandKt(ulong[] workingKey, ulong[] tempKeys)
    {
        var k0 = new ulong[_wordsInBlock];
        var k1 = new ulong[_wordsInBlock];

        _state = new ulong[_wordsInBlock];
        _state[0] += (ulong)(_wordsInBlock + _wordsInKey + 1);

        if (_wordsInBlock == _wordsInKey)
        {
            Array.Copy(workingKey, k0, _wordsInBlock);
            Array.Copy(workingKey, k1, _wordsInBlock);
        }
        else
        {
            Array.Copy(workingKey, 0, k0, 0, _wordsInBlock);
            Array.Copy(workingKey, _wordsInBlock, k1, 0, _wordsInBlock);
        }

        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] += k0[i];
        Round();
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] ^= k1[i];
        Round();
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] += k0[i];
        Round();

        Array.Copy(_state, tempKeys, _wordsInBlock);
    }

    private void WorkingKeyExpandEven(ulong[] workingKey, ulong[] tempKey)
    {
        var initialData = (ulong[])workingKey.Clone();
        var tempRoundKey = new ulong[_wordsInBlock];
        int round = 0;
        ulong tmv = 0x0001000100010001UL;

        while (true)
        {
            EvenRoundKey(initialData, 0, tempKey, tmv, tempRoundKey, round);
            if (_rounds == round)
                break;

            if (_wordsInBlock != _wordsInKey)
            {
                round += 2;
                tmv <<= 1;
                EvenRoundKey(initialData, _wordsInBlock, tempKey, tmv, tempRoundKey, round);
                if (_rounds == round)
                    break;
            }

            round += 2;
            tmv <<= 1;

            ulong first = initialData[0];
            Array.Copy(initialData, 1, initialData, 0, initialData.Length - 1);
            initialData[^1] = first;
        }
    }

    private void EvenRoundKey(ulong[] initialData, int offset, ulong[] tempKey, ulong tmv, ulong[] tempRoundKey, int round)
    {
        for (int i = 0; i < _wordsInBlock; i++)
            tempRoundKey[i] = tempKey[i] + tmv;
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] = initialData[offset + i] + tempRoundKey[i];
        Round();
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] ^= tempRoundKey[i];
        Round();
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] += tempRoundKey[i];
        Array.Copy(_state, _roundKeys![round], _wordsInBlock);
    }

    private void WorkingKeyExpandOdd()
    {
        for (int round = 1; round < _rounds; round += 2)
            RotateLeft(_roundKeys![round - 1], _roundKeys[round]);
    }

    /// <summary>Odd round keys: the previous even key rotated left by 2w + 3 bytes (w = words in block).</summary>
    private void RotateLeft(ulong[] x, ulong[] z)
    {
        switch (_wordsInBlock)
        {
            case 2:
                z[0] = (x[0] >> 56) | (x[1] << 8);
                z[1] = (x[1] >> 56) | (x[0] << 8);
                break;
            case 4:
                z[0] = (x[1] >> 24) | (x[2] << 40);
                z[1] = (x[2] >> 24) | (x[3] << 40);
                z[2] = (x[3] >> 24) | (x[0] << 40);
                z[3] = (x[0] >> 24) | (x[1] << 40);
                break;
            default:
                for (int i = 0; i < 8; i++)
                    z[i] = (x[(i + 2) & 7] >> 24) | (x[(i + 3) & 7] << 40);
                break;
        }
    }

    private void Round()
    {
        SubBytes();
        ShiftRows();
        MixColumns();
    }

    // ---------------------------------------------------------------------------------------------
    // Round transformations
    // ---------------------------------------------------------------------------------------------

    private void SubBytes() => Substitute(DstuSBoxes.Pi);

    private void InvSubBytes() => Substitute(DstuSBoxes.InversePi);

    /// <summary>Row r (byte r of every column) goes through S-box r mod 4.</summary>
    private void Substitute(byte[][] s)
    {
        byte[] s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3];
        for (int i = 0; i < _wordsInBlock; i++)
        {
            ulong u = _state[i];
            _state[i] = s0[(int)(u & 0xFF)]
                        | ((ulong)s1[(int)((u >> 8) & 0xFF)] << 8)
                        | ((ulong)s2[(int)((u >> 16) & 0xFF)] << 16)
                        | ((ulong)s3[(int)((u >> 24) & 0xFF)] << 24)
                        | ((ulong)s0[(int)((u >> 32) & 0xFF)] << 32)
                        | ((ulong)s1[(int)((u >> 40) & 0xFF)] << 40)
                        | ((ulong)s2[(int)((u >> 48) & 0xFF)] << 48)
                        | ((ulong)s3[(int)(u >> 56)] << 56);
        }
    }

    /// <summary>Row r rotates right by r·c/8 columns (c columns); done as masked swaps, as in BouncyCastle.</summary>
    private void ShiftRows()
    {
        ulong[] s = _state;
        switch (_wordsInBlock)
        {
            case 2:
                Swap(ref s[0], ref s[1], 0xFFFFFFFF00000000UL);
                break;
            case 4:
                Swap(ref s[0], ref s[2], 0xFFFFFFFF00000000UL);
                Swap(ref s[1], ref s[3], 0x0000FFFFFFFF0000UL);
                Swap(ref s[0], ref s[1], 0xFFFF0000FFFF0000UL);
                Swap(ref s[2], ref s[3], 0xFFFF0000FFFF0000UL);
                break;
            default:
                Swap(ref s[0], ref s[4], 0xFFFFFFFF00000000UL);
                Swap(ref s[1], ref s[5], 0x00FFFFFFFF000000UL);
                Swap(ref s[2], ref s[6], 0x0000FFFFFFFF0000UL);
                Swap(ref s[3], ref s[7], 0x000000FFFFFFFF00UL);
                Swap(ref s[0], ref s[2], 0xFFFF0000FFFF0000UL);
                Swap(ref s[1], ref s[3], 0x00FFFF0000FFFF00UL);
                Swap(ref s[4], ref s[6], 0xFFFF0000FFFF0000UL);
                Swap(ref s[5], ref s[7], 0x00FFFF0000FFFF00UL);
                Swap(ref s[0], ref s[1], 0xFF00FF00FF00FF00UL);
                Swap(ref s[2], ref s[3], 0xFF00FF00FF00FF00UL);
                Swap(ref s[4], ref s[5], 0xFF00FF00FF00FF00UL);
                Swap(ref s[6], ref s[7], 0xFF00FF00FF00FF00UL);
                break;
        }
    }

    private void InvShiftRows()
    {
        ulong[] s = _state;
        switch (_wordsInBlock)
        {
            case 2:
                Swap(ref s[0], ref s[1], 0xFFFFFFFF00000000UL);
                break;
            case 4:
                Swap(ref s[0], ref s[1], 0xFFFF0000FFFF0000UL);
                Swap(ref s[2], ref s[3], 0xFFFF0000FFFF0000UL);
                Swap(ref s[0], ref s[2], 0xFFFFFFFF00000000UL);
                Swap(ref s[1], ref s[3], 0x0000FFFFFFFF0000UL);
                break;
            default:
                Swap(ref s[0], ref s[1], 0xFF00FF00FF00FF00UL);
                Swap(ref s[2], ref s[3], 0xFF00FF00FF00FF00UL);
                Swap(ref s[4], ref s[5], 0xFF00FF00FF00FF00UL);
                Swap(ref s[6], ref s[7], 0xFF00FF00FF00FF00UL);
                Swap(ref s[0], ref s[2], 0xFFFF0000FFFF0000UL);
                Swap(ref s[1], ref s[3], 0x00FFFF0000FFFF00UL);
                Swap(ref s[4], ref s[6], 0xFFFF0000FFFF0000UL);
                Swap(ref s[5], ref s[7], 0x00FFFF0000FFFF00UL);
                Swap(ref s[0], ref s[4], 0xFFFFFFFF00000000UL);
                Swap(ref s[1], ref s[5], 0x00FFFFFFFF000000UL);
                Swap(ref s[2], ref s[6], 0x0000FFFFFFFF0000UL);
                Swap(ref s[3], ref s[7], 0x000000FFFFFFFF00UL);
                break;
        }
    }

    /// <summary>Exchanges the bits selected by <paramref name="mask"/> between a and b.</summary>
    private static void Swap(ref ulong a, ref ulong b, ulong mask)
    {
        ulong d = (a ^ b) & mask;
        a ^= d;
        b ^= d;
    }

    private void MixColumns()
    {
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] = MixColumn(_state[i]);
    }

    private void MixColumnsInv()
    {
        for (int i = 0; i < _wordsInBlock; i++)
            _state[i] = MixColumnInv(_state[i]);
    }

    /// <summary>Column times the circulant MDS matrix (01, 01, 05, 01, 08, 06, 07, 04) over GF(2^8)/x^8+x^4+x^3+x^2+1.</summary>
    private static ulong MixColumn(ulong c)
    {
        ulong x1 = MulX(c);
        ulong u = Rotate(8, c) ^ c;
        u ^= Rotate(16, u);
        u ^= Rotate(48, c);
        ulong v = MulX2(u ^ c ^ x1);
        return u ^ Rotate(32, v) ^ Rotate(40, x1) ^ Rotate(48, x1);
    }

    /// <summary>Column times the inverse matrix (AD, 95, 76, A8, 2F, 49, D7, CA).</summary>
    private static ulong MixColumnInv(ulong c)
    {
        ulong u0 = c;
        u0 ^= Rotate(8, u0);
        u0 ^= Rotate(32, u0);
        u0 ^= Rotate(48, c);

        ulong t = u0 ^ c;
        ulong c48 = Rotate(48, c);
        ulong c56 = Rotate(56, c);

        ulong u7 = t ^ c56;
        ulong u6 = Rotate(56, t);
        u6 ^= MulX(u7);
        ulong u5 = Rotate(16, t) ^ c;
        u5 ^= Rotate(40, MulX(u6) ^ c);
        ulong u4 = t ^ c48;
        u4 ^= MulX(u5);
        ulong u3 = Rotate(16, u0);
        u3 ^= MulX(u4);
        ulong u2 = t ^ Rotate(24, c) ^ c48 ^ c56;
        u2 ^= MulX(u3);
        ulong u1 = Rotate(32, t) ^ c ^ c56;
        u1 ^= MulX(u2);
        u0 ^= MulX(Rotate(40, u1));
        return u0;
    }

    /// <summary>Every byte times x in GF(2^8).</summary>
    private static ulong MulX(ulong n) =>
        ((n & 0x7F7F7F7F7F7F7F7FUL) << 1) ^ (((n & 0x8080808080808080UL) >> 7) * 0x1DUL);

    /// <summary>Every byte times x^2 in GF(2^8).</summary>
    private static ulong MulX2(ulong n) =>
        ((n & 0x3F3F3F3F3F3F3F3FUL) << 2)
        ^ (((n & 0x8080808080808080UL) >> 6) * 0x1DUL)
        ^ (((n & 0x4040404040404040UL) >> 6) * 0x1DUL);

    private static ulong Rotate(int n, ulong x) => (x >> n) | (x << (64 - n));
}
