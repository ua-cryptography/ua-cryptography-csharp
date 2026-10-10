namespace UA.Cryptography.Dstu7624;

// Translated to C# from BouncyCastle Java 1.86 (KGMac; MIT licence, see THIRD-PARTY-NOTICES.md).
// The whole message is processed at once; BouncyCastle's streaming interface is not reproduced.

/// <summary>GMAC of DSTU 7624 (KGMac): GCM with an empty plaintext, the message being associated data.</summary>
public sealed class Dstu7624Gmac
{
    private readonly Dstu7624Gcm _gcm;

    public Dstu7624Gmac(int blockBits, ReadOnlySpan<byte> key)
    {
        _gcm = new Dstu7624Gcm(blockBits, key);
    }

    public byte[] ComputeMac(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> data, int macBits) =>
        _gcm.Encrypt(nonce, data, ReadOnlySpan<byte>.Empty, macBits);
}
