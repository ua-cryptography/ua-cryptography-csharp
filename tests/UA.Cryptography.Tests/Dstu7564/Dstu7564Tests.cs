using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using UA.Cryptography.Dstu7564;

namespace UA.Cryptography.Tests.Dstu7564;

public class Dstu7564Tests
{
    /// <summary>"seq:n" stands for the n bytes 00 01 02 ... (n − 1), the messages of the standard's examples.</summary>
    private static byte[] Message(string spec) => spec.StartsWith("seq:")
        ? Enumerable.Range(0, int.Parse(spec.Substring(4))).Select(i => (byte)i).ToArray()
        : Convert.FromHexString(spec);

    /// <summary>
    /// Examples of DSTU 7564:2014 / the Kupyna paper (Oliynykov et al., 2015); the same set is used by the
    /// BouncyCastle test suite (DSTU7564Test).
    /// </summary>
    [Theory]
    [InlineData(256, "seq:64", "08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875")]
    [InlineData(256, "seq:128", "0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882")]
    [InlineData(256, "seq:256", "D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F")]
    [InlineData(256, "FF", "EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4")]
    [InlineData(256, "seq:95", "1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16")]
    [InlineData(256, "seq:0", "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6")]
    [InlineData(384, "seq:95", "D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8")]
    [InlineData(512, "seq:64", "3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A")]
    [InlineData(512, "seq:128", "76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE")]
    [InlineData(512, "seq:256", "0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E")]
    [InlineData(512, "FF", "871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292")]
    [InlineData(512, "seq:192", "B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121")]
    [InlineData(512, "seq:0", "656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538")]
    public void StandardExamples(int bits, string message, string expected)
    {
        Assert.Equal(expected, Convert.ToHexString(Dstu7564Hash.HashData(Message(message), bits)));
    }

    [Theory]
    [InlineData("", "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6")]
    [InlineData("a", "C51A1D639596FB613D86557314A150C40F8FFF3DE48BC93A3B03C161F4105EE4")]
    [InlineData("abc", "0BD1B36109F1318411A0517315AA46B8839DF06622A278676F5487996C9CFC04")]
    [InlineData("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "02621DBB53F2C7001BE64D7308ECB80D21BA7797C92E98D1EFC240D41E4C414B")]
    public void AsciiMessages(string message, string expected)
    {
        Assert.Equal(expected, Convert.ToHexString(Dstu7564Hash.HashData(Encoding.ASCII.GetBytes(message))));
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public void MatchesBouncyCastle(int bits)
    {
        var random = new Random(bits);
        using var ours = new Dstu7564Hash(bits);
        // around both block sizes (64 and 128 bytes) and the 12-byte length field
        foreach (int length in new[] { 0, 1, 51, 52, 53, 63, 64, 65, 115, 116, 117, 127, 128, 129, 1000, 4097 })
        {
            var data = new byte[length];
            random.NextBytes(data);
            var bc = new Dstu7564Digest(bits);
            bc.BlockUpdate(data, 0, data.Length);
            var expected = new byte[bits / 8];
            bc.DoFinal(expected, 0);
            Assert.Equal(expected, ours.ComputeHash(data));
        }
    }

    [Fact]
    public void IncrementalHashingMatchesOneShot()
    {
        var data = new byte[1001];
        new Random(2).NextBytes(data);
        foreach (int bits in new[] { 256, 512 })
        {
            using var h = new Dstu7564Hash(bits);
            int offset = 0;
            foreach (int chunk in new[] { 1, 63, 2, 128, 300, 7 })
            {
                h.TransformBlock(data, offset, chunk, null, 0);
                offset += chunk;
            }
            h.TransformFinalBlock(data, offset, data.Length - offset);
            Assert.Equal(Dstu7564Hash.HashData(data, bits), h.Hash);
        }
    }

    [Fact]
    public void UnsupportedSizeIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Dstu7564Hash(128));
    }
}
