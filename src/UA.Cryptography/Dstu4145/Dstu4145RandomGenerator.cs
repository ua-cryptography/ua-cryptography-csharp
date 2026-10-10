using System.Buffers.Binary;
using System.Security.Cryptography;
using UA.Cryptography.Gost;

namespace UA.Cryptography.Dstu4145;

/// <summary>
/// Random bit generator of DSTU 4145-2002, Appendix A, built on GOST 28147-89 in simple substitution mode.
/// </summary>
/// <remarks>
/// <para>
/// State: secret key k (256 bits), secret seed s (64 bits), I = E_k(D) where D is the current date and time.
/// Every call produces one bit: x = E_k(I ⊕ s), s = E_k(x ⊕ I), the output is the least significant bit of x.
/// </para>
/// <para>
/// Bytes are filled most significant bit first, so the first generated bit becomes the leading bit of an integer
/// read in big-endian order, as 6.3 and 6.4 prescribe. The generator is only as good as its key and seed: both must
/// come from a physical source of randomness and be kept secret. It is slow by design (two block encryptions per
/// bit); the library uses <see cref="RandomNumberGenerator"/> unless an instance of this class is passed in.
/// </para>
/// </remarks>
public sealed class Dstu4145RandomGenerator : RandomNumberGenerator
{
    private readonly Gost28147 _cipher;
    private readonly byte[] _i = new byte[8];
    private readonly byte[] _s = new byte[8];

    /// <param name="key">Secret 32-byte key k of GOST 28147.</param>
    /// <param name="seed">Secret 8-byte initial value s.</param>
    /// <param name="dateTime">64-bit date and time value D; the current UTC ticks when null.</param>
    /// <param name="sbox">GOST 28147 substitution table (128 entries); DKE No. 1 when omitted.</param>
    public Dstu4145RandomGenerator(ReadOnlySpan<byte> key, ReadOnlySpan<byte> seed, ulong? dateTime = null, ReadOnlySpan<byte> sbox = default)
    {
        if (seed.Length != 8)
            throw new ArgumentException("The seed s must be 8 bytes long.", nameof(seed));
        _cipher = new Gost28147(sbox.Length == 0 ? Gost28147.ExpandDke(Gost34311.DefaultDke) : sbox);
        _cipher.SetKey(key);
        seed.CopyTo(_s);

        Span<byte> d = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(d, dateTime ?? (ulong)DateTime.UtcNow.Ticks);
        _cipher.EncryptBlock(d, _i); // I = E_k(D)
    }

    /// <summary>Creates a generator whose key and seed are taken from the operating system's CSPRNG.</summary>
    public static Dstu4145RandomGenerator CreateSeeded()
    {
        Span<byte> key = stackalloc byte[32];
        Span<byte> seed = stackalloc byte[8];
        Fill(key);
        Fill(seed);
        var generator = new Dstu4145RandomGenerator(key, seed);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(seed);
        return generator;
    }

    /// <summary>Produces the next bit (0 or 1).</summary>
    public int NextBit()
    {
        Span<byte> t = stackalloc byte[8];
        Span<byte> x = stackalloc byte[8];
        for (int j = 0; j < 8; j++)
            t[j] = (byte)(_i[j] ^ _s[j]);
        _cipher.EncryptBlock(t, x);          // x = E_k(I ⊕ s)
        for (int j = 0; j < 8; j++)
            t[j] = (byte)(x[j] ^ _i[j]);
        _cipher.EncryptBlock(t, _s);         // s = E_k(x ⊕ I)
        return x[0] & 1;                     // x_0, the rightmost bit of x
    }

    public override void GetBytes(byte[] data) => GetBytes(data.AsSpan());

    public override void GetBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            int b = 0;
            for (int k = 0; k < 8; k++)
                b = (b << 1) | NextBit();
            data[i] = (byte)b;
        }
    }

    public override void GetNonZeroBytes(byte[] data) => GetNonZeroBytes(data.AsSpan());

    public override void GetNonZeroBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            do
            {
                GetBytes(data.Slice(i, 1));
            }
            while (data[i] == 0);
        }
    }
}
