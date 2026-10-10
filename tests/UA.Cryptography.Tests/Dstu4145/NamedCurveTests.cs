using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Dstu4145;

public class NamedCurveTests
{
    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void ParametersAreValid(string basis, int m)
    {
        Assert.Null(RecommendedCurves.Get(basis, m).Validate());
    }

    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void SignAndVerify(string basis, int m)
    {
        var parameters = RecommendedCurves.Get(basis, m);
        var signer = new Dstu4145Signer(parameters);
        Dstu4145KeyPair key = signer.GenerateKeyPair();
        Assert.Null(parameters.ValidatePublicKey(key.PublicKey));

        byte[] hash = RandomNumberGenerator.GetBytes(32);
        byte[] signature = signer.SignHash(key.PrivateKey, hash);
        Assert.Equal(parameters.MinimumSignatureBits / 8, signature.Length);
        Assert.True(signer.VerifyHash(key.PublicKey, hash, signature));

        // Longer signature encodings are accepted too (5.7: any L_D ≥ 2 L(n), multiple of 16).
        byte[] longSignature = signer.SignHash(key.PrivateKey, hash, parameters.MinimumSignatureBits + 64);
        Assert.True(signer.VerifyHash(key.PublicKey, hash, longSignature));

        byte[] badHash = (byte[])hash.Clone();
        badHash[^1] ^= 0x01; // the low bits of the hash always enter h (5.9)
        Assert.False(signer.VerifyHash(key.PublicKey, badHash, signature));

        Dstu4145KeyPair other = signer.GenerateKeyPair();
        Assert.False(signer.VerifyHash(other.PublicKey, hash, signature));
    }

    [Fact]
    public void PublishedOnbCurvesAreFrobeniusImagesOfTableG2()
    {
        // Values of table 2.2 published by the 2010 cryptography.org.ua project ("Рекомендованные кривые") that
        // differ from table Г.2: the same curves seen through a power of the Frobenius map.
        var published = new (int M, int J, string B, string X, string Y)[]
        {
            (179, 94, "19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB",
                "11F4112265410477159E0D3E39BC4AC4ADE43B21B66B9", "2CA5F0B34C61A86216F13766591CB266E2819EE582B3C"),
            (191, 190, "13871C9D29D6CEEA740FD57444F72FDBAE559C13A1E31EF8",
                "7159E0D3E39BC4AC4ADE43B21B66B94F2AF25ABEEB1D85D3", "57E45D546BE6201E9705E029535D009D31F51D81E18226BE"),
            (431, 234, "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299",
                "2020182CFCD7C724157B363D4ABFD4C16251773C595D4E5C88572FA9D5EBB58142326448C08D3EE3E17E40B835D3090DCFBA7C5ADEA6",
                "18E1B6EFB28EEF8A1F9C1859ED57C74CA747E4E1A60294C005D1920E80903A432929855828DD7F21714F837E119A044987F00110ADAD"),
        };
        foreach (var a in published)
        {
            var p = Dstu4145NamedCurves.OptimalNormal(a.M);
            Assert.Equal(Hex.ToBigInteger(a.B), p.Curve.B.SquareTimes(a.J).ToBigInteger());
            Assert.Equal(Hex.ToBigInteger(a.X), p.BasePoint.AffineX.SquareTimes(a.J).ToBigInteger());
            Assert.Equal(Hex.ToBigInteger(a.Y), p.BasePoint.AffineY.SquareTimes(a.J).ToBigInteger());

            // and the published point is a valid base point of the published curve
            var publishedCurve = new BinaryCurve(p.Field, p.Curve.A, p.Field.FromHex(a.B));
            CurvePoint g = publishedCurve.CreatePoint(a.X, a.Y);
            Assert.True(publishedCurve.Multiply(g, p.N).IsInfinity);
        }
    }

    [Fact]
    public void BasePointGeneration()
    {
        // 7.3: a freshly computed base point is valid.
        var p = Dstu4145NamedCurves.OptimalNormal(173);
        CurvePoint g = Dstu4145DomainParameters.ComputeBasePoint(p.Curve, p.N);
        var generated = new Dstu4145DomainParameters(p.Curve, g, p.N);
        Assert.Null(generated.Validate());
    }

    [Fact]
    public void ValidationDetectsBrokenParameters()
    {
        var p = Dstu4145NamedCurves.Polynomial(163);
        Assert.NotNull(new Dstu4145DomainParameters(p.Curve, p.BasePoint, p.N + 2).Validate()); // not prime / order
        Assert.NotNull(new Dstu4145DomainParameters(p.Curve, p.Curve.Infinity, p.N).Validate());
        Assert.NotNull(p.ValidatePublicKey(p.Curve.Infinity));
        CurvePoint random = p.Curve.RandomPoint();
        // A random point has order 2n with probability 1/2; retry until we get one outside the subgroup.
        for (int i = 0; i < 64 && p.Curve.Multiply(random, p.N).IsInfinity; i++)
            random = p.Curve.RandomPoint();
        Assert.NotNull(p.ValidatePublicKey(random));
    }

    [Fact]
    public void MovCondition()
    {
        foreach (int m in Dstu4145NamedCurves.PolynomialDegrees)
            Assert.True(Dstu4145DomainParameters.SatisfiesMovCondition(Dstu4145NamedCurves.Polynomial(m).N, m));
        // 2^m = 1 mod n for n = 2^m - 1
        BigInteger mersenne = (BigInteger.One << 127) - 1;
        Assert.False(Dstu4145DomainParameters.SatisfiesMovCondition(mersenne, 127));
    }

    [Fact]
    public void SignatureEncoding()
    {
        var (r, s) = (Hex.ToBigInteger("ABCDEF"), Hex.ToBigInteger("123456"));
        byte[] d = Dstu4145Encoding.EncodeSignature(r, s, 64);
        Assert.Equal("00123456" + "00ABCDEF", Convert.ToHexString(d));
        Assert.Equal((r, s), Dstu4145Encoding.DecodeSignature(d));
        Assert.Throws<ArgumentException>(() => Dstu4145Encoding.EncodeSignature(r, s, 60));
        Assert.Throws<ArgumentException>(() => Dstu4145Encoding.EncodeSignature(BigInteger.One << 40, s, 64));
    }
}
