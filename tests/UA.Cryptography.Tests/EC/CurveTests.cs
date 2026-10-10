using System.Numerics;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.EC;

public class CurveTests
{
    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void LadderMatchesAffineDoubleAndAdd(string basis, int m)
    {
        var p = RecommendedCurves.Get(basis, m);
        BinaryCurve c = p.Curve;
        var random = new Random(m);
        for (int i = 0; i < 2; i++)
        {
            BigInteger k = TestUtil.RandomInteger(random, (int)p.N.GetBitLength());
            Assert.Equal(c.MultiplyDoubleAndAdd(p.BasePoint, k), c.Multiply(p.BasePoint, k));
        }
    }

    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void ScalarMultiplicationEdgeCases(string basis, int m)
    {
        var p = RecommendedCurves.Get(basis, m);
        BinaryCurve c = p.Curve;
        CurvePoint g = p.BasePoint;
        BigInteger n = p.N;

        Assert.True(c.Multiply(g, 0).IsInfinity);
        Assert.Equal(g, c.Multiply(g, 1));
        Assert.Equal(c.Double(g), c.Multiply(g, 2));
        Assert.Equal(c.Add(c.Double(g), g), c.Multiply(g, 3));
        Assert.Equal(g.Negate(), c.Multiply(g, n - 1));
        Assert.True(c.Multiply(g, n).IsInfinity);
        Assert.Equal(g, c.Multiply(g, n + 1));
        Assert.Equal(g.Negate(), c.Multiply(g, -1));
        Assert.True(c.Multiply(c.Infinity, 12345).IsInfinity);

        var random = new Random(m + 1);
        foreach (BigInteger k in new[] { BigInteger.One, 2, n - 1, n - 2, TestUtil.RandomInteger(random, 100), TestUtil.RandomInteger(random, m) % n })
            Assert.Equal(c.Multiply(g, k), c.MultiplyFixedLength(g, k, n));
    }

    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void GroupLaw(string basis, int m)
    {
        var p = RecommendedCurves.Get(basis, m);
        BinaryCurve c = p.Curve;
        var random = new Random(m + 2);
        CurvePoint a = c.Multiply(p.BasePoint, TestUtil.RandomInteger(random, 64));
        CurvePoint b = c.Multiply(p.BasePoint, TestUtil.RandomInteger(random, 64));
        CurvePoint d = c.RandomPoint();

        Assert.True(c.IsOnCurve(a) && c.IsOnCurve(b) && c.IsOnCurve(d));
        Assert.Equal(a + b, b + a);
        Assert.Equal((a + b) + d, a + (b + d));
        Assert.True((a + a.Negate()).IsInfinity);
        Assert.Equal(a, a + c.Infinity);
        Assert.Equal(a.Twice(), a + a);
        Assert.True(c.IsOnCurve(a + d));

        // (k1 + k2) P = k1 P + k2 P
        BigInteger k1 = TestUtil.RandomInteger(random, m), k2 = TestUtil.RandomInteger(random, m);
        Assert.Equal(c.Multiply(d, k1 + k2), c.Multiply(d, k1) + c.Multiply(d, k2));
    }

    [Theory]
    [MemberData(nameof(RecommendedCurves.All), MemberType = typeof(RecommendedCurves))]
    public void PointCompressionRoundTrip(string basis, int m)
    {
        var p = RecommendedCurves.Get(basis, m);
        BinaryCurve c = p.Curve;
        var random = new Random(m + 3);
        for (int i = 0; i < 3; i++)
        {
            CurvePoint q = c.Multiply(p.BasePoint, TestUtil.RandomInteger(random, m) % p.N);
            BigInteger compressed = c.Compress(q);
            Assert.Equal(q, c.Decompress(compressed));
        }
    }

    [Fact]
    public void PointOfOrderTwo()
    {
        var p = Dstu4145NamedCurves.Polynomial(163);
        BinaryCurve c = p.Curve;
        CurvePoint t = c.CreatePoint(c.Field.Zero, c.B.Sqrt());
        Assert.True(c.Double(t).IsInfinity);
        Assert.True(c.Multiply(t, 2).IsInfinity);
        Assert.Equal(t, c.Multiply(t, 3));
        Assert.Equal(t, c.Decompress(BigInteger.Zero));
    }

    [Theory]
    [InlineData("PB", 163)]
    [InlineData("ONB", 173)]
    public void PointsOutsideTheSubgroup(string basis, int m)
    {
        // The curve order is h·n with h = 2 or 4. For a point R of even order, (order/2)·R is the point of order 2,
        // (0, sqrt(B)), so the ladder must pass through and finish at x = 0 correctly.
        var p = RecommendedCurves.Get(basis, m);
        BinaryCurve c = p.Curve;
        CurvePoint t = c.CreatePoint(c.Field.Zero, c.B.Sqrt());
        for (int i = 0; i < 8; i++)
        {
            CurvePoint r = c.RandomPoint();
            CurvePoint nr = c.Multiply(r, p.N);
            Assert.Equal(c.MultiplyDoubleAndAdd(r, p.N), nr);
            Assert.True(nr.IsInfinity || nr.Equals(t) || c.Double(nr).Equals(t) || c.Double(nr).IsInfinity);
            Assert.True(c.Multiply(r, 4 * p.N).IsInfinity);
        }
    }

    [Fact]
    public void PointNotOnCurveIsRejected()
    {
        var p = Dstu4145NamedCurves.OptimalNormal(173);
        CurvePoint g = p.BasePoint;
        Assert.Throws<ArgumentException>(() => p.Curve.CreatePoint(g.AffineX, g.AffineX));
    }
}
