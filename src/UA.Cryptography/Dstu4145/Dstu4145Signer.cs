using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.EC;
using UA.Cryptography.Gost;
using UA.Cryptography.Math;

namespace UA.Cryptography.Dstu4145;

/// <summary>Pre-signature (F_e, e) of section 11. Must be used for one signature only and then destroyed.</summary>
public sealed record Dstu4145Presignature(BigInteger E, FieldElement Fe);

/// <summary>Key pair: private key d and public key Q = −dP (section 9).</summary>
public sealed record Dstu4145KeyPair(BigInteger PrivateKey, CurvePoint PublicKey);

/// <summary>
/// DSTU 4145-2002 digital signature: key generation (9), pre-signature (11), signing (12) and verification (13).
/// </summary>
/// <remarks>
/// <see cref="SignMessage"/> / <see cref="VerifyMessage"/> hash the message with GOST 34.311 (6.2).
/// <see cref="SignHash"/> / <see cref="VerifyHash"/> take a ready hash code H(T) as bytes, most significant first
/// (see <see cref="Dstu4145Encoding.HashToFieldElement"/>), so any other hash function can be used.
/// Randomness comes from the operating system's <see cref="RandomNumberGenerator"/> unless another generator is
/// passed in, for example <see cref="Dstu4145RandomGenerator"/> of Appendix A.
/// </remarks>
public sealed class Dstu4145Signer
{
    private readonly RandomNumberGenerator? _rng; // null: the system CSPRNG

    public Dstu4145Signer(Dstu4145DomainParameters parameters, RandomNumberGenerator? rng = null)
    {
        Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        _rng = rng;
    }

    public Dstu4145DomainParameters Parameters { get; }

    private BinaryCurve Curve => Parameters.Curve;

    private BigInteger N => Parameters.N;

    // --------------------------------------------------------------------------------------------
    // Keys (section 9)
    // --------------------------------------------------------------------------------------------

    /// <summary>9.1 – 9.2: random private key d ≠ 0 and public key Q = −dP.</summary>
    public Dstu4145KeyPair GenerateKeyPair()
    {
        BigInteger d;
        do
        {
            d = Parameters.RandomInteger(_rng);
        }
        while (d.IsZero);
        return new Dstu4145KeyPair(d, ComputePublicKey(d));
    }

    /// <summary>9.2: Q = −dP.</summary>
    public CurvePoint ComputePublicKey(BigInteger privateKey)
    {
        CheckPrivateKey(privateKey);
        return Curve.MultiplyFixedLength(Parameters.BasePoint, privateKey, N).Negate();
    }

    // --------------------------------------------------------------------------------------------
    // Pre-signature (section 11)
    // --------------------------------------------------------------------------------------------

    /// <summary>Section 11: random e and F_e = x(eP), x(eP) ≠ 0.</summary>
    public Dstu4145Presignature ComputePresignature()
    {
        while (true)
        {
            BigInteger e = Parameters.RandomInteger(_rng);
            if (e.IsZero)
                continue;
            Dstu4145Presignature? presignature = ComputePresignature(e);
            if (presignature is not null)
                return presignature;
        }
    }

    /// <summary>
    /// Section 11 for a given e (for tests and pre-computation). Returns null when x(eP) = 0,
    /// in which case another e must be chosen.
    /// </summary>
    public Dstu4145Presignature? ComputePresignature(BigInteger e)
    {
        if (e.Sign <= 0 || e >= N)
            throw new ArgumentOutOfRangeException(nameof(e), "0 < e < n is required.");
        CurvePoint r = Curve.MultiplyFixedLength(Parameters.BasePoint, e, N);
        if (r.IsInfinity || r.AffineX.IsZero)
            return null;
        return new Dstu4145Presignature(e, r.AffineX);
    }

    // --------------------------------------------------------------------------------------------
    // Signing (section 12)
    // --------------------------------------------------------------------------------------------

    /// <summary>
    /// Section 12: signs a hash code and returns the signature D of <paramref name="signatureBits"/> bits
    /// (big-endian bytes). Pass 0 to use the shortest admissible length.
    /// </summary>
    public byte[] SignHash(BigInteger privateKey, ReadOnlySpan<byte> hash, int signatureBits = 0)
    {
        if (signatureBits == 0)
            signatureBits = Parameters.MinimumSignatureBits;
        CheckSignatureLength(signatureBits);
        FieldElement h = HashElement(hash);

        while (true)
        {
            var (r, s) = Sign(privateKey, h, ComputePresignature()) ?? (BigInteger.Zero, BigInteger.Zero);
            if (!r.IsZero)
                return Dstu4145Encoding.EncodeSignature(r, s, signatureBits);
        }
    }

    /// <summary>
    /// Steps 9 – 13 of section 12 with an explicit pre-signature. Returns null when r = 0 or s = 0,
    /// in which case the caller must take another pre-signature.
    /// </summary>
    public (BigInteger R, BigInteger S)? Sign(BigInteger privateKey, FieldElement h, Dstu4145Presignature presignature)
    {
        CheckPrivateKey(privateKey);
        ArgumentNullException.ThrowIfNull(presignature);
        if (h.IsZero)
            h = Parameters.Field.One; // step 7

        FieldElement y = h * presignature.Fe;                         // step 9
        BigInteger r = Dstu4145Encoding.FieldElementToInteger(y, N);  // step 10
        if (r.IsZero)
            return null;
        BigInteger s = (presignature.E + privateKey * r) % N;         // step 12
        if (s.IsZero)
            return null;
        return (r, s);
    }

    /// <summary>
    /// Section 12 with the GOST 34.311 hash: H(T) is computed with <paramref name="hash"/> (default DKE when null)
    /// and converted to the binary string of 5.6 (the digest bytes reversed).
    /// </summary>
    public byte[] SignMessage(BigInteger privateKey, ReadOnlySpan<byte> message, int signatureBits = 0, Gost34311? hash = null) =>
        SignHash(privateKey, HashMessage(message, hash), signatureBits);

    /// <summary>
    /// H(T) by GOST 34.311 as the binary string (h_255, ..., h_0) of 5.6, most significant byte first.
    /// </summary>
    public static byte[] HashMessage(ReadOnlySpan<byte> message, Gost34311? hash = null)
    {
        byte[] digest;
        if (hash is null)
        {
            digest = Gost34311.HashData(message);
        }
        else
        {
            hash.Initialize();
            digest = hash.ComputeHash(message.ToArray());
        }
        Array.Reverse(digest);
        return digest;
    }

    // --------------------------------------------------------------------------------------------
    // Verification (section 13)
    // --------------------------------------------------------------------------------------------

    /// <summary>Section 13: verifies the signature D (big-endian bytes) of a hash code.</summary>
    public bool VerifyHash(CurvePoint publicKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
    {
        int signatureBits = signature.Length * 8;
        if (signatureBits % 16 != 0 || signatureBits < 2 * Dstu4145Encoding.BitLength(N))
            return false; // step 3
        var (r, s) = Dstu4145Encoding.DecodeSignature(signature);
        return Verify(publicKey, HashElement(hash), r, s);
    }

    /// <summary>Section 13 with the GOST 34.311 hash (see <see cref="SignMessage"/>).</summary>
    public bool VerifyMessage(CurvePoint publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, Gost34311? hash = null) =>
        VerifyHash(publicKey, HashMessage(message, hash), signature);

    /// <summary>Steps 10 – 15 of section 13.</summary>
    /// <remarks>
    /// The public key is not checked here (10.1 allows skipping it when keys are stored safely). Every
    /// <see cref="CurvePoint"/> lies on the curve, but a key obtained by decompression may lie outside the subgroup of
    /// order n; call <see cref="Dstu4145DomainParameters.ValidatePublicKey"/> for keys from untrusted sources.
    /// </remarks>
    public bool Verify(CurvePoint publicKey, FieldElement h, BigInteger r, BigInteger s)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (!Curve.Equals(publicKey.Curve) || publicKey.IsInfinity)
            return false;
        if (r.Sign <= 0 || r >= N || s.Sign <= 0 || s >= N)
            return false;
        if (h.IsZero)
            h = Parameters.Field.One;

        CurvePoint rPoint = Curve.Multiply(Parameters.BasePoint, s) + Curve.Multiply(publicKey, r); // R = sP + rQ
        if (rPoint.IsInfinity)
            return false;
        FieldElement y = h * rPoint.AffineX;
        return Dstu4145Encoding.FieldElementToInteger(y, N) == r;
    }

    private FieldElement HashElement(ReadOnlySpan<byte> hash)
    {
        if (hash.Length == 0)
            throw new ArgumentException("Empty hash.", nameof(hash));
        FieldElement h = Dstu4145Encoding.HashToFieldElement(hash, Parameters.Field);
        return h.IsZero ? Parameters.Field.One : h;
    }

    private void CheckPrivateKey(BigInteger d)
    {
        if (d.Sign <= 0 || d >= N)
            throw new ArgumentOutOfRangeException(nameof(d), "The private key must satisfy 0 < d < n.");
    }

    private void CheckSignatureLength(int bits)
    {
        if (bits % 16 != 0 || bits < 2 * Dstu4145Encoding.BitLength(N))
            throw new ArgumentException("L_D must be a multiple of 16 and at least 2 L(n) (12.3).", nameof(bits));
    }
}
