using System.Numerics;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Math;

public class FieldTests
{
    public static TheoryData<int> PolynomialDegrees()
    {
        var data = new TheoryData<int>();
        foreach (int m in Dstu4145NamedCurves.PolynomialTable.Keys)
            data.Add(m);
        return data;
    }

    public static TheoryData<int> NormalDegrees()
    {
        var data = new TheoryData<int>();
        foreach (int m in OptimalNormalBasisField.StandardDegrees)
            data.Add(m);
        return data;
    }

    private static BinaryField CreateField(string basis, int m) => basis == "PB"
        ? Dstu4145NamedCurves.CreatePolynomialBasisField(m)
        : new OptimalNormalBasisField(m);

    public static TheoryData<string, int> AllFields()
    {
        var data = new TheoryData<string, int>();
        foreach (int m in Dstu4145NamedCurves.PolynomialTable.Keys)
            data.Add("PB", m);
        foreach (int m in OptimalNormalBasisField.StandardDegrees)
            data.Add("ONB", m);
        return data;
    }

    [Theory]
    [MemberData(nameof(PolynomialDegrees))]
    public void Table1PolynomialsAreIrreducible(int m)
    {
        Assert.True(Dstu4145NamedCurves.CreatePolynomialBasisField(m).IsIrreducible());
    }

    [Fact]
    public void ReducibleTrinomialIsDetected()
    {
        // t^163 + t^3 + 1 is not irreducible (the recommended pentanomial is used for m = 163).
        Assert.False(new PolynomialBasisField(163, 3).IsIrreducible());
    }

    [Fact]
    public void Table2DegreesHaveTypeTwoBasis()
    {
        foreach (int m in OptimalNormalBasisField.StandardDegrees)
            Assert.True(OptimalNormalBasisField.HasTypeTwoBasis(m), m.ToString());
        Assert.False(OptimalNormalBasisField.HasTypeTwoBasis(163));
        Assert.False(OptimalNormalBasisField.HasTypeTwoBasis(257));
    }

    [Theory]
    [MemberData(nameof(AllFields))]
    public void FieldAxioms(string basis, int m)
    {
        BinaryField f = CreateField(basis, m);
        var random = new Random(m);
        for (int i = 0; i < 10; i++)
        {
            FieldElement a = TestUtil.RandomElement(f, random);
            FieldElement b = TestUtil.RandomElement(f, random);
            FieldElement c = TestUtil.RandomElement(f, random);

            Assert.Equal(a * b, b * a);
            Assert.Equal((a * b) * c, a * (b * c));
            Assert.Equal(a * (b + c), a * b + a * c);
            Assert.Equal(a, a * f.One);
            Assert.True((a * f.Zero).IsZero);
            Assert.Equal(a * a, a.Square());
            Assert.Equal(a, a.SquareTimes(m)); // a^(2^m) = a
            if (!a.IsZero)
                Assert.Equal(f.One, a * a.Invert());
            Assert.Equal(a, a.Sqrt().Square());
        }
    }

    [Theory]
    [MemberData(nameof(AllFields))]
    public void RoundTripThroughStandardRepresentation(string basis, int m)
    {
        BinaryField f = CreateField(basis, m);
        var random = new Random(m + 1);
        for (int i = 0; i < 20; i++)
        {
            BigInteger v = TestUtil.RandomInteger(random, m);
            Assert.Equal(v, f.FromBigInteger(v).ToBigInteger());
        }
        Assert.Throws<ArgumentOutOfRangeException>(() => f.FromBigInteger(BigInteger.One << m));
    }

    [Theory]
    [MemberData(nameof(AllFields))]
    public void TraceAndHalfTrace(string basis, int m)
    {
        BinaryField f = CreateField(basis, m);
        var random = new Random(m + 2);
        Assert.Equal(1, f.One.Trace()); // m is odd
        Assert.Equal(0, f.Zero.Trace());
        for (int i = 0; i < 4; i++)
        {
            FieldElement a = TestUtil.RandomElement(f, random);
            Assert.Equal(f.TraceByDefinition(a.Value), a.Trace());

            // For tr(a) = 0 the half-trace solves z^2 + z = a.
            FieldElement v = a.Trace() == 0 ? a : a + f.One;
            FieldElement z = v.HalfTrace();
            Assert.Equal(v, z.Square() + z);
        }
    }

    [Fact]
    public void OnbUnitIsAllOnesAndSquaringIsRotation()
    {
        foreach (int m in OptimalNormalBasisField.StandardDegrees)
        {
            var f = new OptimalNormalBasisField(m);
            BigInteger mask = (BigInteger.One << m) - 1;
            Assert.Equal(mask, f.One.ToBigInteger()); // 5.3

            var random = new Random(m);
            BigInteger v = TestUtil.RandomInteger(random, m);
            BigInteger rotatedRight = (v >> 1) | ((v & 1) << (m - 1)); // В.4: squaring is a cyclic shift right
            Assert.Equal(rotatedRight, f.FromBigInteger(v).Square().ToBigInteger());
        }
    }

    /// <summary>
    /// Independent reference: Gaussian normal basis multiplication of ANSI X9.62 / IEEE 1363 (A.3.8),
    /// written directly over bit arrays without any of the tricks used by the library.
    /// </summary>
    private static BigInteger ReferenceOnbMultiply(int m, BigInteger x, BigInteger y)
    {
        int p = 2 * m + 1;
        // F(k) = i where k = ±2^i mod p
        var fTable = new int[p];
        int w = 1;
        for (int i = 0; i < m; i++)
        {
            fTable[w] = i;
            fTable[p - w] = i;
            w = 2 * w % p;
        }

        // u[i] = coefficient of x^(2^i): the leftmost bit of the standard representation is i = 0 (5.3).
        int[] u = Enumerable.Range(0, m).Select(i => (int)((x >> (m - 1 - i)) & 1)).ToArray();
        int[] v = Enumerable.Range(0, m).Select(i => (int)((y >> (m - 1 - i)) & 1)).ToArray();
        var c = new int[m];
        for (int k = 0; k < m; k++)
        {
            int sum = 0;
            for (int j = 1; j <= p - 2; j++)
                sum ^= u[fTable[j + 1]] & v[fTable[p - j]];
            c[k] = sum;
            u = u.Skip(1).Append(u[0]).ToArray(); // cyclic shift left
            v = v.Skip(1).Append(v[0]).ToArray();
        }

        BigInteger r = BigInteger.Zero;
        for (int i = 0; i < m; i++)
        {
            if (c[i] != 0)
                r |= BigInteger.One << (m - 1 - i);
        }
        return r;
    }

    [Theory]
    [MemberData(nameof(NormalDegrees))]
    public void OnbMultiplicationMatchesX962Reference(int m)
    {
        var f = new OptimalNormalBasisField(m);
        var random = new Random(m * 7);
        for (int i = 0; i < 3; i++)
        {
            BigInteger a = TestUtil.RandomInteger(random, m);
            BigInteger b = TestUtil.RandomInteger(random, m);
            Assert.Equal(ReferenceOnbMultiply(m, a, b), (f.FromBigInteger(a) * f.FromBigInteger(b)).ToBigInteger());
        }
    }

    [Fact]
    public void OnbMultiplicationOfBasisElements()
    {
        // Every pair of basis elements, small field: exhaustive check of the folding logic against the reference.
        foreach (int m in new[] { 5, 9, 11, 23 }) // 2m + 1 = 11, 19, 23, 47
        {
            if (!OptimalNormalBasisField.HasTypeTwoBasis(m))
                continue;
            var f = new OptimalNormalBasisField(m);
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    BigInteger a = BigInteger.One << i, b = BigInteger.One << j;
                    Assert.Equal(ReferenceOnbMultiply(m, a, b), (f.FromBigInteger(a) * f.FromBigInteger(b)).ToBigInteger());
                }
            }
        }
    }

    [Fact]
    public void PortableAndHardwarePathsAgree()
    {
        // Full-field check with the portable carry-less multiplication forced on.
        var pb = Dstu4145NamedCurves.CreatePolynomialBasisField(431);
        var onb = new OptimalNormalBasisField(431);
        var random = new Random(11);
        var expected = new List<BigInteger>();
        var inputs = new List<(BigInteger, BigInteger)>();
        for (int i = 0; i < 10; i++)
            inputs.Add((TestUtil.RandomInteger(random, 431), TestUtil.RandomInteger(random, 431)));
        foreach (var (a, b) in inputs)
        {
            expected.Add((pb.FromBigInteger(a) * pb.FromBigInteger(b)).ToBigInteger());
            expected.Add((onb.FromBigInteger(a) * onb.FromBigInteger(b)).ToBigInteger());
        }

        lock (typeof(Gf2Poly))
        {
            bool saved = Gf2Poly.UseHardware;
            Gf2Poly.UseHardware = false;
            try
            {
                int k = 0;
                foreach (var (a, b) in inputs)
                {
                    Assert.Equal(expected[k++], (pb.FromBigInteger(a) * pb.FromBigInteger(b)).ToBigInteger());
                    Assert.Equal(expected[k++], (onb.FromBigInteger(a) * onb.FromBigInteger(b)).ToBigInteger());
                }
            }
            finally
            {
                Gf2Poly.UseHardware = saved;
            }
        }
    }

    [Fact]
    public void QuadraticEquation()
    {
        foreach (BinaryField f in new BinaryField[] { Dstu4145NamedCurves.CreatePolynomialBasisField(163), new OptimalNormalBasisField(173) })
        {
            var random = new Random(f.M);
            var z = new ulong[f.Words];
            int solved = 0;
            for (int i = 0; i < 20; i++)
            {
                FieldElement u = TestUtil.RandomElement(f, random);
                FieldElement w = TestUtil.RandomElement(f, random);
                int k = f.SolveQuadratic(u.Value, w.Value, z);
                if (k == 0)
                    continue;
                solved++;
                var zz = new FieldElement(f, (ulong[])z.Clone());
                Assert.Equal(w, zz.Square() + u * zz);
            }
            Assert.True(solved > 3);

            // u = 0: z = sqrt(w)
            FieldElement w0 = TestUtil.RandomElement(f, random);
            Assert.Equal(1, f.SolveQuadratic(f.Zero.Value, w0.Value, z));
            Assert.Equal(w0, new FieldElement(f, (ulong[])z.Clone()).Square());
        }
    }
}

public class FieldEqualityTests
{
    [Fact]
    public void SeparatelyCreatedFieldsInteroperate()
    {
        var f1 = new OptimalNormalBasisField(173);
        var f2 = new OptimalNormalBasisField(173);
        Assert.Equal(f1, f2);
        Assert.Equal(f1.FromHex("ABCDEF"), f2.FromHex("ABCDEF"));
        Assert.Equal((f1.FromHex("1234") * f1.FromHex("5678")).ToBigInteger(), (f1.FromHex("1234") * f2.FromHex("5678")).ToBigInteger());

        var p1 = new PolynomialBasisField(163, 3, 6, 7);
        Assert.NotEqual<BinaryField>(p1, new PolynomialBasisField(163, 1, 2, 8));
        Assert.Throws<ArgumentException>(() => p1.FromHex("1") * f1.FromHex("1"));
    }
}
