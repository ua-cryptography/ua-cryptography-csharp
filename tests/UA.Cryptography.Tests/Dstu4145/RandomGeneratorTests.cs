using System.Numerics;
using System.Text;
using UA.Cryptography.Dstu4145;

namespace UA.Cryptography.Tests.Dstu4145;

/// <summary>The random bit generator of Appendix A (<see cref="Dstu4145RandomGenerator"/>).</summary>
public class RandomGeneratorTests
{
    [Fact]
    public void GeneratorIsDeterministicForFixedState()
    {
        byte[] key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8 };
        var a = new Dstu4145RandomGenerator(key, seed, dateTime: 0x0123456789ABCDEF);
        var b = new Dstu4145RandomGenerator(key, seed, dateTime: 0x0123456789ABCDEF);
        var c = new Dstu4145RandomGenerator(key, seed, dateTime: 0x0123456789ABCDEE);
        byte[] ra = new byte[64], rb = new byte[64], rc = new byte[64];
        a.GetBytes(ra);
        b.GetBytes(rb);
        c.GetBytes(rc);
        Assert.Equal(ra, rb);
        Assert.NotEqual(ra, rc);
    }

    [Fact]
    public void GeneratorOutputLooksBalanced()
    {
        using var g = Dstu4145RandomGenerator.CreateSeeded();
        var bytes = new byte[2048];
        g.GetBytes(bytes);
        int ones = bytes.Sum(b => BitOperations.PopCount(b));
        // 16384 bits: expect 8192 ± 4.5 sigma (sigma = 64)
        Assert.InRange(ones, 8192 - 290, 8192 + 290);
    }

    [Fact]
    public void SignerWorksWithTheStandardGenerator()
    {
        var parameters = Dstu4145NamedCurves.OptimalNormal(173);
        using var g = Dstu4145RandomGenerator.CreateSeeded();
        var signer = new Dstu4145Signer(parameters, g);
        var key = signer.GenerateKeyPair();
        byte[] message = Encoding.UTF8.GetBytes("Тестове повідомлення");
        byte[] signature = signer.SignMessage(key.PrivateKey, message);
        Assert.True(signer.VerifyMessage(key.PublicKey, message, signature));
    }
}
