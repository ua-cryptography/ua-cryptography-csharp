using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using UA.Cryptography.Dstu4145;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcDstu4145NamedCurves = Org.BouncyCastle.Asn1.UA.Dstu4145NamedCurves;
using BcDstu4145Signer = Org.BouncyCastle.Crypto.Signers.Dstu4145Signer;
using BigInteger = System.Numerics.BigInteger;

namespace UA.Cryptography.Tests.Dstu4145;

/// <summary>
/// Cross-checks the polynomial basis against BouncyCastle, an independent and widely used implementation
/// of DSTU 4145 (BouncyCastle supports only the polynomial basis).
/// </summary>
public class BouncyCastleCrossCheckTests
{
    private static BigInteger ToBig(BcBigInteger v) => new(v.ToByteArrayUnsigned(), isUnsigned: true, isBigEndian: true);

    private static BcBigInteger ToBc(BigInteger v) => new(1, v.ToByteArray(isUnsigned: true, isBigEndian: true));

    public static TheoryData<int> BcCurveIndices()
    {
        var data = new TheoryData<int>();
        for (int i = 0; i < BcDstu4145NamedCurves.GetOids().Length; i++)
            data.Add(i);
        return data;
    }

    private static (ECDomainParameters Bc, Dstu4145DomainParameters Ours) Pair(int index)
    {
        DerObjectIdentifier oid = BcDstu4145NamedCurves.GetOids()[index];
        ECDomainParameters bc = BcDstu4145NamedCurves.GetByOid(oid);
        var f2m = (F2mCurve)bc.Curve;
        return (bc, Dstu4145NamedCurves.Polynomial(f2m.M));
    }

    [Theory]
    [MemberData(nameof(BcCurveIndices))]
    public void NamedCurvesMatchBouncyCastle(int index)
    {
        var (bc, ours) = Pair(index);
        var f2m = (F2mCurve)bc.Curve;
        var field = (UA.Cryptography.Math.PolynomialBasisField)ours.Field;

        Assert.Equal(field.K, f2m.K1);
        Assert.Equal(field.J, f2m.K2);
        Assert.Equal(field.L, f2m.K3);
        Assert.Equal(ToBig(f2m.A.ToBigInteger()), ours.Curve.A.ToBigInteger());
        Assert.Equal(ToBig(f2m.B.ToBigInteger()), ours.Curve.B.ToBigInteger());
        Assert.Equal(ToBig(bc.N), ours.N);

        Org.BouncyCastle.Math.EC.ECPoint g = bc.G.Normalize();
        Assert.Equal(ToBig(g.AffineXCoord.ToBigInteger()), ours.BasePoint.AffineX.ToBigInteger());
        Assert.Equal(ToBig(g.AffineYCoord.ToBigInteger()), ours.BasePoint.AffineY.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(BcCurveIndices))]
    public void ScalarMultiplicationMatchesBouncyCastle(int index)
    {
        var (bc, ours) = Pair(index);
        var random = new Random(index);
        for (int i = 0; i < 3; i++)
        {
            BigInteger k = TestUtil.RandomInteger(random, ours.Field.M) % ours.N;
            Org.BouncyCastle.Math.EC.ECPoint expected = bc.G.Multiply(ToBc(k)).Normalize();
            UA.Cryptography.EC.CurvePoint actual = ours.Curve.Multiply(ours.BasePoint, k);
            Assert.Equal(ToBig(expected.AffineXCoord.ToBigInteger()), actual.AffineX.ToBigInteger());
            Assert.Equal(ToBig(expected.AffineYCoord.ToBigInteger()), actual.AffineY.ToBigInteger());
        }
    }

    [Theory]
    [MemberData(nameof(BcCurveIndices))]
    public void SignaturesAreInteroperable(int index)
    {
        var (bc, ours) = Pair(index);
        var signer = new Dstu4145Signer(ours);
        Dstu4145KeyPair key = signer.GenerateKeyPair();

        var bcPrivate = new ECPrivateKeyParameters(ToBc(key.PrivateKey), bc);
        var bcPublic = new ECPublicKeyParameters(
            bc.Curve.CreatePoint(ToBc(key.PublicKey.AffineX.ToBigInteger()), ToBc(key.PublicKey.AffineY.ToBigInteger())), bc);

        byte[] hash = new SecureRandom().GenerateSeed(32);
        // BouncyCastle treats the hash as a little-endian byte string (as GOST 34.311 outputs it) and reverses it;
        // this library follows the standard's notation, most significant byte first.
        byte[] bcHash = hash.Reverse().ToArray();

        // ours -> BouncyCastle
        byte[] signature = signer.SignHash(key.PrivateKey, hash);
        var (r, s) = Dstu4145Encoding.DecodeSignature(signature);
        var verifier = new BcDstu4145Signer();
        verifier.Init(false, bcPublic);
        Assert.True(verifier.VerifySignature(bcHash, ToBc(r), ToBc(s)));

        // BouncyCastle -> ours
        var bcSigner = new BcDstu4145Signer();
        bcSigner.Init(true, new ParametersWithRandom(bcPrivate, new SecureRandom()));
        BcBigInteger[] rs = bcSigner.GenerateSignature(bcHash);
        Assert.True(signer.Verify(key.PublicKey,
            Dstu4145Encoding.HashToFieldElement(hash, ours.Field), ToBig(rs[0]), ToBig(rs[1])));
    }
}
