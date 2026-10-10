using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using UA.Cryptography.Gost;

namespace UA.Cryptography.Tests.Gost;

/// <summary>GOST 28147-89 and GOST 34.311-95 against BouncyCastle and the published GOST R 34.11-94 vectors.</summary>
public class GostTests
{
    /// <summary>
    /// The substitution tables met in practice: the three DKE found in Ukrainian certificates and the CryptoPro table
    /// of GOST R 34.11-94. The UCC table is the "test" parameter set of GOST R 34.11-94 (BouncyCastle "D-Test").
    /// </summary>
    public static TheoryData<string, string> SBoxes => new()
    {
        { "DKE No. 1 (default)", Expand(Convert.ToHexString(Gost34311.DefaultDke)) },
        { "DKE of UCC = D-Test", Expand("4A92D80E6B1C7F53EB4C6DFA23810759581DA342EFC7609B7DA1089FE46CB2536C715FD84A9E03B24BA0721D36859CFEDB413F590AE7682C1FD057A4923E6B8C") },
        { "DKE of CZO 2005", Expand("8BC217ED36594AF01F74E23DCB9A6058FED7852014ABC3694B08A7359D621ECFE87FD35AB4192C607AEC14D283B0F569B09641AE8F5DC327C7129A6EF48D350B") },
        { "CryptoPro D-A", Convert.ToHexString(Gost28147Engine.GetSBox("D-A")) },
    };

    private static string Expand(string dke) => Convert.ToHexString(Gost28147.ExpandDke(Convert.FromHexString(dke)));

    [Fact]
    public void UccTableIsTheGostR3411TestParameterSet() =>
        Assert.Equal(Convert.ToHexString(Gost28147Engine.GetSBox("D-Test")), SBoxes.ElementAt(1)[1]);

    [Theory]
    [MemberData(nameof(SBoxes))]
    public void BlockCipherMatchesBouncyCastle(string name, string sboxHex)
    {
        byte[] sbox = Convert.FromHexString(sboxHex);
        var random = new Random(name.Length * 31 + sboxHex[7]);
        var ours = new Gost28147(sbox);
        for (int i = 0; i < 50; i++)
        {
            var key = new byte[32];
            var block = new byte[8];
            random.NextBytes(key);
            random.NextBytes(block);

            var bc = new Gost28147Engine();
            bc.Init(true, new ParametersWithSBox(new KeyParameter(key), sbox));
            var expected = new byte[8];
            bc.ProcessBlock(block, 0, expected, 0);

            ours.SetKey(key);
            var actual = new byte[8];
            ours.EncryptBlock(block, actual);
            Assert.Equal(expected, actual);

            var back = new byte[8];
            ours.DecryptBlock(actual, back);
            Assert.Equal(block, back);
        }
    }

    [Theory]
    [MemberData(nameof(SBoxes))]
    public void HashMatchesBouncyCastle(string name, string sboxHex)
    {
        byte[] sbox = Convert.FromHexString(sboxHex);
        var random = new Random(name.Length * 17 + sboxHex[5]);
        using var ours = new Gost34311(sbox);
        foreach (int length in new[] { 0, 1, 31, 32, 33, 63, 64, 65, 100, 1000 })
        {
            var data = new byte[length];
            random.NextBytes(data);
            var bc = new Gost3411Digest(sbox);
            bc.BlockUpdate(data, 0, data.Length);
            var expected = new byte[32];
            bc.DoFinal(expected, 0);
            Assert.Equal(expected, ours.ComputeHash(data));
        }
    }

    [Fact]
    public void IncrementalHashingMatchesOneShot()
    {
        var data = new byte[777];
        new Random(1).NextBytes(data);
        byte[] expected = Gost34311.HashData(data);

        using var h = new Gost34311();
        int offset = 0;
        foreach (int chunk in new[] { 1, 30, 2, 64, 100, 5 })
        {
            h.TransformBlock(data, offset, chunk, null, 0);
            offset += chunk;
        }
        h.TransformFinalBlock(data, offset, data.Length - offset);
        Assert.Equal(expected, h.Hash);
    }

    /// <summary>Published GOST R 34.11-94 test vectors with the "test" parameter set (RFC 5831, Wikipedia).</summary>
    [Theory]
    [InlineData("", "CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D")]
    [InlineData("a", "D42C539E367C66E9C88A801F6649349C21871B4344C6A573F849FDCE62F314DD")]
    [InlineData("message digest", "AD4434ECB18F2C99B60CBE59EC3D2469582B65273F48DE72DB2FDE16A4889A4D")]
    [InlineData("The quick brown fox jumps over the lazy dog", "77B7FA410C9AC58A25F49BCA7D0468C9296529315EACA76BD1A10F376D1F4294")]
    public void PublishedVectorsWithTestParameters(string message, string expected)
    {
        using var h = new Gost34311(Gost28147Engine.GetSBox("D-Test"));
        Assert.Equal(expected, Convert.ToHexString(h.ComputeHash(Encoding.ASCII.GetBytes(message))));
    }

    [Theory]
    [InlineData("", "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0")]
    [InlineData("message digest", "BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0")]
    public void PublishedVectorsWithCryptoProParameters(string message, string expected)
    {
        using var h = new Gost34311(Gost28147Engine.GetSBox("D-A"));
        Assert.Equal(expected, Convert.ToHexString(h.ComputeHash(Encoding.ASCII.GetBytes(message))));
    }
}
