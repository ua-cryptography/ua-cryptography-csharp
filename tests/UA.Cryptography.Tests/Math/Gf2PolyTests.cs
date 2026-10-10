using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Math;

public class Gf2PolyTests
{
    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 3)]
    [InlineData(3, 3)]
    [InlineData(4, 7)]
    [InlineData(8, 8)]
    [InlineData(16, 16)]
    public void SoftwareMultiplicationMatchesNaive(int wa, int wb)
    {
        var random = new Random(wa * 100 + wb);
        for (int iter = 0; iter < 20; iter++)
        {
            ulong[] a = TestUtil.RandomWords(random, wa);
            ulong[] b = TestUtil.RandomWords(random, wb);
            if (iter == 0)
            {
                Array.Fill(a, ulong.MaxValue); // all top bits set: exercises the overflow repair
                Array.Fill(b, ulong.MaxValue);
            }
            var r = new ulong[wa + wb];
            Gf2Poly.MultiplySoftware(a, b, r);
            Assert.Equal(TestUtil.NaiveMultiply(a, b), r);
        }
    }

    [Fact]
    public void HardwareMultiplicationMatchesSoftware()
    {
        if (!Gf2Poly.HardwareSupported)
            return; // nothing to compare on this CPU
        var random = new Random(7);
        for (int iter = 0; iter < 200; iter++)
        {
            int w = 1 + iter % 9;
            ulong[] a = TestUtil.RandomWords(random, w);
            ulong[] b = TestUtil.RandomWords(random, w);
            var hw = new ulong[2 * w];
            var sw = new ulong[2 * w];
            Gf2Poly.MultiplyHardware(a, b, hw);
            Gf2Poly.MultiplySoftware(a, b, sw);
            Assert.Equal(sw, hw);
        }
    }

    [Fact]
    public void SquareMatchesMultiplication()
    {
        var random = new Random(3);
        for (int iter = 0; iter < 50; iter++)
        {
            ulong[] a = TestUtil.RandomWords(random, 1 + iter % 8);
            var sq = new ulong[2 * a.Length];
            Gf2Poly.Square(a, sq);
            Assert.Equal(TestUtil.NaiveMultiply(a, a), sq);
        }
    }

    [Fact]
    public void ReverseBits()
    {
        var random = new Random(5);
        for (int iter = 0; iter < 200; iter++)
        {
            ulong x = (ulong)random.NextInt64() * 3;
            ulong expected = 0;
            for (int i = 0; i < 64; i++)
                expected |= ((x >> i) & 1) << (63 - i);
            Assert.Equal(expected, Gf2Poly.ReverseBitsPortable(x));
            Assert.Equal(expected, Gf2Poly.ReverseBits(x));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(130)]
    public void ShiftsAreInverse(int shift)
    {
        var random = new Random(shift);
        ulong[] a = TestUtil.RandomWords(random, 4);
        var left = new ulong[8];
        Gf2Poly.ShiftLeft(a, shift, left);
        var back = new ulong[4];
        Gf2Poly.ShiftRight(left, shift, back);
        Assert.Equal(a, back);

        // in place
        var b = (ulong[])left.Clone();
        Gf2Poly.ShiftRight(b, shift, b);
        Assert.Equal(a, b.Take(4).ToArray());
        Assert.All(b.Skip(4), w => Assert.Equal(0UL, w));
    }
}
