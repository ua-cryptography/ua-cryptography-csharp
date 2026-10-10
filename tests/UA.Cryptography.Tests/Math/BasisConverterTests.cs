using System.Numerics;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Math;

public class BasisConverterTests
{
    private static BasisConverter Create(int m) =>
        new(Dstu4145NamedCurves.CreatePolynomialBasisField(m), new OptimalNormalBasisField(m));

    [Theory]
    [MemberData(nameof(FieldTests.NormalDegrees), MemberType = typeof(FieldTests))]
    public void ConversionIsFieldIsomorphism(int m)
    {
        BasisConverter c = Create(m);
        var random = new Random(m);
        Assert.Equal(c.Polynomial.One, c.ToPolynomial(c.Normal.One));
        for (int i = 0; i < 5; i++)
        {
            FieldElement a = TestUtil.RandomElement(c.Normal, random);
            FieldElement b = TestUtil.RandomElement(c.Normal, random);
            Assert.Equal(a, c.ToNormal(c.ToPolynomial(a)));
            Assert.Equal(c.ToPolynomial(a * b), c.ToPolynomial(a) * c.ToPolynomial(b));
            Assert.Equal(c.ToPolynomial(a + b), c.ToPolynomial(a) + c.ToPolynomial(b));

            FieldElement u = TestUtil.RandomElement(c.Polynomial, random);
            Assert.Equal(u, c.ToPolynomial(c.ToNormal(u)));
        }
    }

    [Theory]
    [MemberData(nameof(FieldTests.NormalDegrees), MemberType = typeof(FieldTests))]
    public void NormalElementIsRootOfNormalPolynomial(int m)
    {
        // В.2: the normal polynomial built by the recurrence has x as a root.
        BasisConverter c = Create(m);
        BigInteger p = BasisConverter.NormalPolynomial(m);
        Assert.Equal(m, (int)p.GetBitLength() - 1);
        FieldElement acc = c.Polynomial.Zero;
        for (int i = m; i >= 0; i--)
        {
            acc *= c.NormalElement;
            if (!((p >> i) & 1).IsZero)
                acc += c.Polynomial.One;
        }
        Assert.True(acc.IsZero);
    }

    [Fact]
    public void ConversionIsDeterministic()
    {
        BasisConverter a = Create(173), b = Create(173);
        Assert.Equal(a.NormalElement.ToBigInteger(), b.NormalElement.ToBigInteger());
    }

    public static TheoryData<int> CommonDegrees()
    {
        var data = new TheoryData<int>();
        foreach (int m in Dstu4145NamedCurves.NormalDegrees)
        {
            if (Dstu4145NamedCurves.PolynomialDegrees.Contains(m))
                data.Add(m);
        }
        return data;
    }

    /// <summary>
    /// The curves of table Г.2 are the curves of table Г.1 written in the normal basis: after a change of basis
    /// (with a suitable root of the normal polynomial) the coefficient B coincides bit for bit.
    /// This also confirms the bit order of the normal basis representation for every curve of Г.2.
    /// </summary>
    [Theory]
    [MemberData(nameof(CommonDegrees))]
    public void TableG2IsTableG1InNormalBasis(int m)
    {
        var pb = Dstu4145NamedCurves.Polynomial(m);
        var onb = Dstu4145NamedCurves.OptimalNormal(m);
        Assert.Equal(pb.N, onb.N);

        var field = (PolynomialBasisField)pb.Field;
        var c = new BasisConverter(field, (OptimalNormalBasisField)onb.Field).AlignedTo(pb.Curve.B, onb.Curve.B);
        BinaryCurve converted = c.Convert(pb.Curve);
        Assert.Equal(onb.Curve.B, converted.B);
        Assert.Equal(onb.Curve.A.IsZero, converted.A.IsZero);

        // The converted base point of Г.1 is a valid generator of the same subgroup on the Г.2 curve.
        CurvePoint g = c.Convert(pb.BasePoint, onb.Curve);
        Assert.True(onb.Curve.Multiply(g, onb.N).IsInfinity);
    }

    [Theory]
    [MemberData(nameof(CommonDegrees))]
    public void ScalarMultiplicationCommutesWithChangeOfBasis(int m)
    {
        var pb = Dstu4145NamedCurves.Polynomial(m);
        var c = new BasisConverter((PolynomialBasisField)pb.Field, (OptimalNormalBasisField)Dstu4145NamedCurves.OptimalNormal(m).Field);
        BinaryCurve onbCurve = c.Convert(pb.Curve);
        CurvePoint gOnb = c.Convert(pb.BasePoint, onbCurve);

        var random = new Random(m);
        for (int i = 0; i < 3; i++)
        {
            BigInteger k = TestUtil.RandomInteger(random, m) % pb.N;
            CurvePoint expected = c.Convert(pb.Curve.Multiply(pb.BasePoint, k), onbCurve);
            Assert.Equal(expected, onbCurve.Multiply(gOnb, k));
        }
    }

    [Fact]
    public void KeysConvertButSignaturesAreBoundToTheBasis()
    {
        var pb = Dstu4145NamedCurves.Polynomial(233);
        var c = new BasisConverter((PolynomialBasisField)pb.Field, new OptimalNormalBasisField(233));
        BinaryCurve onbCurve = c.Convert(pb.Curve);
        var onb = new Dstu4145DomainParameters(onbCurve, c.Convert(pb.BasePoint, onbCurve), pb.N);
        Assert.Null(onb.Validate());

        var pbSigner = new Dstu4145Signer(pb);
        var onbSigner = new Dstu4145Signer(onb);
        Dstu4145KeyPair key = pbSigner.GenerateKeyPair();
        CurvePoint q = c.Convert(key.PublicKey, onbCurve);
        Assert.Equal(onbSigner.ComputePublicKey(key.PrivateKey), q); // Q = -dP in either basis

        FieldElement h = TestUtil.RandomElement(pb.Field, new Random(1));
        var (r, s) = pbSigner.Sign(key.PrivateKey, h, pbSigner.ComputePresignature())!.Value;
        Assert.True(pbSigner.Verify(key.PublicKey, h, r, s));

        // R = sP + rQ is the same point, but r is cut from the bit string of h·x_R (5.8), which depends on the basis.
        Assert.False(onbSigner.Verify(q, c.ToNormal(h), r, s));
    }
}
