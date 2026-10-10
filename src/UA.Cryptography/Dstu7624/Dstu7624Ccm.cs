using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (KCCMBlockCipher; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>
/// Authenticated encryption CCM of DSTU 7624 ("вироблення імітовставки та гамування", KCCMBlockCipher).
/// Output of encryption: ciphertext ‖ tag. The nonce (≤ one block) is zero-padded on the right; Nb (4, 6 or 8)
/// bounds the message length (Nb = 4: up to 2^32 − 1 bits); the tag is 64, 128, 256, 384 or 512 bits, at most a block.
/// </summary>
public sealed class Dstu7624Ccm
{
    private readonly Dstu7624Engine _engine;
    private readonly int _nb;

    public Dstu7624Ccm(int blockBits, ReadOnlySpan<byte> key, int nb = 4)
    {
        if (nb is not (4 or 6 or 8))
            throw new ArgumentOutOfRangeException(nameof(nb), "Nb must be 4, 6 or 8.");
        _engine = Dstu7624Util.Engine(blockBits, key, true);
        _nb = nb;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plainText, int macBits)
    {
        int b = _engine.BlockSize, macSize = MacSize(macBits);
        byte[] n = Nonce(nonce);
        byte[] mac = Authenticate(n, associatedData, plainText, macSize);

        var result = new byte[plainText.Length + macSize];
        var s = new byte[b];
        _engine.ProcessBlock(n, s);
        var gamma = new byte[b];
        for (int pos = 0; pos < plainText.Length; pos += b)
        {
            NextGamma(s, gamma);
            int len = System.Math.Min(b, plainText.Length - pos);
            for (int i = 0; i < len; i++)
                result[pos + i] = (byte)(plainText[pos + i] ^ gamma[i]);
        }
        NextGamma(s, gamma);
        for (int i = 0; i < macSize; i++)
            result[plainText.Length + i] = (byte)(gamma[i] ^ mac[i]);
        return result;
    }

    /// <summary>Decrypts ciphertext ‖ tag and verifies the tag; throws <see cref="CryptographicException"/> on failure.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> cipherText, int macBits)
    {
        int b = _engine.BlockSize, macSize = MacSize(macBits);
        if (cipherText.Length < macSize)
            throw new CryptographicException("The ciphertext is shorter than the tag.");
        byte[] n = Nonce(nonce);
        int dataLength = cipherText.Length - macSize;

        var plain = new byte[dataLength];
        var s = new byte[b];
        _engine.ProcessBlock(n, s);
        var gamma = new byte[b];
        for (int pos = 0; pos < dataLength; pos += b)
        {
            NextGamma(s, gamma);
            int len = System.Math.Min(b, dataLength - pos);
            for (int i = 0; i < len; i++)
                plain[pos + i] = (byte)(cipherText[pos + i] ^ gamma[i]);
        }
        NextGamma(s, gamma);
        var received = new byte[macSize];
        for (int i = 0; i < macSize; i++)
            received[i] = (byte)(gamma[i] ^ cipherText[dataLength + i]);

        byte[] expected = Authenticate(n, associatedData, plain, macSize);
        if (!CryptographicOperations.FixedTimeEquals(expected.AsSpan(0, macSize), received))
        {
            CryptographicOperations.ZeroMemory(plain);
            throw new CryptographicException("CCM tag verification failed.");
        }
        return plain;
    }

    private int MacSize(int macBits)
    {
        if (macBits is not (64 or 128 or 256 or 384 or 512) || macBits > _engine.BlockSize * 8)
            throw new ArgumentOutOfRangeException(nameof(macBits), "The tag must be 64, 128, 256, 384 or 512 bits and not longer than the block.");
        return macBits / 8;
    }

    private byte[] Nonce(ReadOnlySpan<byte> nonce)
    {
        int b = _engine.BlockSize;
        if (nonce.Length > b)
            throw new ArgumentException("The nonce is longer than the block.", nameof(nonce));
        var n = new byte[b];
        nonce.CopyTo(n); // left-aligned, zero-padded
        return n;
    }

    /// <summary>s ← s + 1 (little-endian, with carry), gamma = E(s).</summary>
    private void NextGamma(byte[] s, byte[] gamma)
    {
        int carry = 1;
        for (int i = 0; i < s.Length && carry != 0; i++)
        {
            carry += s[i];
            s[i] = (byte)carry;
            carry >>= 8;
        }
        _engine.ProcessBlock(s, gamma);
    }

    /// <summary>The CBC-MAC over G1 (nonce, length, flags), the associated data and the plaintext.</summary>
    private byte[] Authenticate(byte[] nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plainText, int macSize)
    {
        int b = _engine.BlockSize;
        bool hasAad = associatedData.Length > 0;

        var g1 = new byte[b];
        Array.Copy(nonce, g1, b - _nb - 1);
        BinaryPrimitives.WriteInt32LittleEndian(g1.AsSpan(b - _nb - 1), plainText.Length);
        g1[b - 1] = Flag(hasAad, macSize);
        var mac = new byte[b];
        _engine.ProcessBlock(g1, mac);

        if (hasAad)
        {
            var g2 = new byte[b];
            BinaryPrimitives.WriteInt32LittleEndian(g2, associatedData.Length);
            if (associatedData.Length <= b - _nb)
            {
                Dstu7624Util.Xor(g2.AsSpan(_nb, associatedData.Length), associatedData);
                Dstu7624Util.Xor(mac, g2);
                _engine.ProcessBlock(mac, mac);
            }
            else
            {
                Dstu7624Util.Xor(mac, g2);
                _engine.ProcessBlock(mac, mac);
                Absorb(mac, associatedData);
            }
        }

        Absorb(mac, plainText);
        return mac;
    }

    /// <summary>CBC-MAC over whole blocks; a trailing partial block is zero-padded.</summary>
    private void Absorb(byte[] mac, ReadOnlySpan<byte> data)
    {
        int b = _engine.BlockSize;
        for (int pos = 0; pos < data.Length; pos += b)
        {
            int len = System.Math.Min(b, data.Length - pos);
            Dstu7624Util.Xor(mac.AsSpan(0, len), data.Slice(pos, len));
            _engine.ProcessBlock(mac, mac);
        }
    }

    /// <summary>Flags byte of G1: associated data present (bit 7), tag length code (bits 6..4), Nb − 1 (bits 3..0).</summary>
    private byte Flag(bool hasAad, int macSize)
    {
        int code = macSize switch { 8 => 2, 16 => 3, 32 => 4, 48 => 5, _ => 6 };
        return (byte)(((hasAad ? 1 : 0) << 7) | (code << 4) | (_nb - 1));
    }
}
