using System.Security.Cryptography;

namespace UA.Cryptography.Gost;

/// <summary>
/// GOST 34.311-95 hash function (the Ukrainian adoption of GOST R 34.11-94), the default hash of DSTU 4145-2002 (6.2).
/// </summary>
/// <remarks>
/// <para>
/// The 32-byte result is the hash value H as GOST defines it, least significant byte first. The binary string
/// (h_255, ..., h_0) used by DSTU 4145 (5.6, 5.9) is therefore the <i>reversed</i> byte array;
/// <see cref="Dstu4145.Dstu4145Signer.SignMessage"/> takes care of that.
/// </para>
/// <para>
/// The substitution table is a parameter. Ukrainian certificates carry it as a 64-byte DKE;
/// <see cref="DefaultDke"/> is the table used when none is given.
/// </para>
/// </remarks>
public sealed class Gost34311 : HashAlgorithm
{
    /// <summary>
    /// The default substitution table of DSTU 4145 (DKE No. 1), as found in Ukrainian certificates and used as the
    /// default by BouncyCastle (<c>Dstu4145Params.GetDefaultDke()</c>).
    /// </summary>
    public static ReadOnlySpan<byte> DefaultDke => new byte[]
    {
        0xA9, 0xD6, 0xEB, 0x45, 0xF1, 0x3C, 0x70, 0x82, 0x80, 0xC4, 0x96, 0x7B, 0x23, 0x1F, 0x5E, 0xAD,
        0xF6, 0x58, 0xEB, 0xA4, 0xC0, 0x37, 0x29, 0x1D, 0x38, 0xD9, 0x6B, 0xF0, 0x25, 0xCA, 0x4E, 0x17,
        0xF8, 0xE9, 0x72, 0x0D, 0xC6, 0x15, 0xB4, 0x3A, 0x28, 0x97, 0x5F, 0x0B, 0xC1, 0xDE, 0xA3, 0x64,
        0x38, 0xB5, 0x64, 0xEA, 0x2C, 0x17, 0x9F, 0xD0, 0x12, 0x3E, 0x6D, 0xB8, 0xFA, 0xC5, 0x79, 0x04,
    };

    private static readonly byte[] C2 =
    {
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
        0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF,
    };

    private readonly Gost28147 _cipher;
    private readonly byte[] _iv;
    private readonly byte[] _h = new byte[32];
    private readonly byte[] _sum = new byte[32];
    private readonly byte[] _buffer = new byte[32];
    private int _bufferLength;
    private ulong _length; // bytes

    /// <summary>GOST 34.311 with the default DKE and zero initial value.</summary>
    public Gost34311()
        : this(Gost28147.ExpandDke(DefaultDke))
    {
    }

    /// <param name="sbox">128-entry substitution table (see <see cref="Gost28147"/>); use
    /// <see cref="Gost28147.ExpandDke"/> for a 64-byte DKE.</param>
    /// <param name="iv">Initial hash value, 32 bytes; zero when omitted.</param>
    public Gost34311(ReadOnlySpan<byte> sbox, ReadOnlySpan<byte> iv = default)
    {
        _cipher = new Gost28147(sbox);
        if (iv.Length != 0 && iv.Length != 32)
            throw new ArgumentException("The initial value must be 32 bytes long.", nameof(iv));
        _iv = iv.Length == 0 ? new byte[32] : iv.ToArray();
        HashSizeValue = 256;
        Initialize();
    }

    /// <summary>Creates the hash with the substitution table given as a 64-byte DKE.</summary>
    public static Gost34311 FromDke(ReadOnlySpan<byte> dke) => new(Gost28147.ExpandDke(dke));

    /// <summary>One-shot hash with the default DKE.</summary>
    public static byte[] HashData(ReadOnlySpan<byte> data)
    {
        using var h = new Gost34311();
        return h.ComputeHash(data.ToArray());
    }

    public override void Initialize()
    {
        _iv.CopyTo(_h, 0);
        Array.Clear(_sum);
        Array.Clear(_buffer);
        _bufferLength = 0;
        _length = 0;
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize) => HashCore(array.AsSpan(ibStart, cbSize));

    protected override void HashCore(ReadOnlySpan<byte> source)
    {
        _length += (ulong)source.Length;
        while (source.Length > 0)
        {
            int n = System.Math.Min(32 - _bufferLength, source.Length);
            source.Slice(0, n).CopyTo(_buffer.AsSpan(_bufferLength));
            _bufferLength += n;
            source = source.Slice(n);
            if (_bufferLength == 32)
            {
                AddToSum(_buffer);
                Step(_buffer);
                _bufferLength = 0;
            }
        }
    }

    protected override byte[] HashFinal()
    {
        if (_bufferLength > 0)
        {
            // The last block is padded with zeros; the length below counts only the real message bits.
            Array.Clear(_buffer, _bufferLength, 32 - _bufferLength);
            AddToSum(_buffer);
            Step(_buffer);
        }

        var length = new byte[32];
        ulong bits = _length * 8; // messages up to 2^61 bytes
        for (int i = 0; i < 8; i++)
            length[i] = (byte)(bits >> (8 * i));
        Step(length);
        Step(_sum);
        return (byte[])_h.Clone();
    }

    /// <summary>Σ = Σ + M mod 2^256, little-endian.</summary>
    private void AddToSum(ReadOnlySpan<byte> block)
    {
        int carry = 0;
        for (int i = 0; i < 32; i++)
        {
            int s = _sum[i] + block[i] + carry;
            _sum[i] = (byte)s;
            carry = s >> 8;
        }
    }

    /// <summary>Step function H = χ(M, H): key generation, encryption, mixing.</summary>
    private void Step(ReadOnlySpan<byte> m)
    {
        Span<byte> u = stackalloc byte[32];
        Span<byte> v = stackalloc byte[32];
        Span<byte> w = stackalloc byte[32];
        Span<byte> key = stackalloc byte[32];
        Span<byte> s = stackalloc byte[32];
        _h.CopyTo(u);
        m.CopyTo(v);

        for (int i = 0; i < 4; i++)
        {
            if (i > 0)
            {
                A(u);
                if (i == 2)
                {
                    for (int j = 0; j < 32; j++)
                        u[j] ^= C2[j];
                }
                A(v);
                A(v);
            }
            for (int j = 0; j < 32; j++)
                w[j] = (byte)(u[j] ^ v[j]);
            P(w, key);
            _cipher.SetKey(key);
            _cipher.EncryptBlock(_h.AsSpan(8 * i, 8), s.Slice(8 * i, 8)); // s_i = E_Ki(h_i)
        }

        // H = ψ^61(H ⊕ ψ(M ⊕ ψ^12(S)))
        for (int n = 0; n < 12; n++)
            Psi(s);
        for (int j = 0; j < 32; j++)
            s[j] ^= m[j];
        Psi(s);
        for (int j = 0; j < 32; j++)
            s[j] ^= _h[j];
        for (int n = 0; n < 61; n++)
            Psi(s);
        s.CopyTo(_h);
    }

    /// <summary>A(y4 ‖ y3 ‖ y2 ‖ y1) = (y1 ⊕ y2) ‖ y4 ‖ y3 ‖ y2 (64-bit blocks, y1 first in memory).</summary>
    private static void A(Span<byte> y)
    {
        Span<byte> t = stackalloc byte[8];
        for (int j = 0; j < 8; j++)
            t[j] = (byte)(y[j] ^ y[j + 8]);
        y.Slice(8, 24).CopyTo(y);
        t.CopyTo(y.Slice(24));
    }

    /// <summary>Byte permutation φ(i + 1 + 4(k − 1)) = 8i + k.</summary>
    private static void P(ReadOnlySpan<byte> w, Span<byte> key)
    {
        for (int k = 0; k < 8; k++)
        {
            key[4 * k] = w[k];
            key[4 * k + 1] = w[8 + k];
            key[4 * k + 2] = w[16 + k];
            key[4 * k + 3] = w[24 + k];
        }
    }

    /// <summary>ψ: shift the sixteen 16-bit words, the new top word is the XOR of words 1, 2, 3, 4, 13, 16.</summary>
    private static void Psi(Span<byte> y)
    {
        byte lo = (byte)(y[0] ^ y[2] ^ y[4] ^ y[6] ^ y[24] ^ y[30]);
        byte hi = (byte)(y[1] ^ y[3] ^ y[5] ^ y[7] ^ y[25] ^ y[31]);
        y.Slice(2, 30).CopyTo(y);
        y[30] = lo;
        y[31] = hi;
    }
}
