using Org.BouncyCastle.Asn1;
using UA.Cryptography.Pki.Asn1;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BigInteger = System.Numerics.BigInteger;
using KeyUsage = Org.BouncyCastle.Asn1.X509.KeyUsage;

namespace UA.Cryptography.Tests.Pki.Asn1;

/// <summary>
/// The package's DER encoder and reader against BouncyCastle: the same bytes for every primitive and for SET OF
/// ordering, BER forms accepted on input, and malformed input rejected.
/// </summary>
public class DerTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("-1")]
    [InlineData("127")]
    [InlineData("128")]
    [InlineData("255")]
    [InlineData("256")]
    [InlineData("-128")]
    [InlineData("-129")]
    [InlineData("-32768")]
    [InlineData("123456789012345678901234567890123456789012345678901234567890")]
    [InlineData("-123456789012345678901234567890123456789012345678901234567890")]
    public void IntegerMatchesBouncyCastle(string value)
    {
        byte[] ours = Der.Integer(BigInteger.Parse(value));
        Assert.Equal(new DerInteger(new BcBigInteger(value)).GetDerEncoded(), ours);
        Assert.Equal(BigInteger.Parse(value), Asn1Node.Parse(ours).GetInteger());
    }

    [Theory]
    [InlineData("1.2.804.2.1.1.1.1.3.1.1")]
    [InlineData("1.2.804.2.1.1.1.1.3.6.1.1")]
    [InlineData("1.2.840.113549.1.9.16.2.47")]
    [InlineData("2.5.29.15")]
    [InlineData("0.9.2342.19200300.100.1.1")]
    [InlineData("2.999.1")]
    [InlineData("1.3.6.1.4.1.18446744073709551616.5")]
    public void ObjectIdentifierMatchesBouncyCastle(string oid)
    {
        byte[] ours = Der.ObjectIdentifier(oid);
        Assert.Equal(new DerObjectIdentifier(oid).GetDerEncoded(), ours);
        Assert.Equal(oid, Asn1Node.Parse(ours).GetOid());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(65535)]
    [InlineData(65536)]
    public void LengthFormsMatchBouncyCastle(int length)
    {
        byte[] content = new byte[length];
        new Random(length).NextBytes(content);
        byte[] ours = Der.OctetString(content);
        Assert.Equal(new DerOctetString(content).GetDerEncoded(), ours);
        Assert.Equal(content, Asn1Node.Parse(ours).GetOctetString());
    }

    [Fact]
    public void SetOfIsSortedLikeBouncyCastle()
    {
        var random = new Random(4145);
        for (int round = 0; round < 50; round++)
        {
            byte[][] items = Enumerable.Range(0, random.Next(1, 8))
                .Select(_ => Der.OctetString(Enumerable.Range(0, random.Next(0, 5)).Select(_ => (byte)random.Next(3)).ToArray()))
                .ToArray();
            var bc = new DerSet(items.Select(i => (Asn1Encodable)Asn1Object.FromByteArray(i)).ToArray());
            Assert.Equal(bc.GetDerEncoded(), Der.SetOf(items));
        }
    }

    [Theory]
    [InlineData(KeyUsage.DigitalSignature)]
    [InlineData(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation)]
    [InlineData(KeyUsage.KeyCertSign | KeyUsage.CrlSign)]
    [InlineData(KeyUsage.KeyAgreement)]
    [InlineData(KeyUsage.DecipherOnly)]
    public void NamedBitsMatchBouncyCastle(int bcUsage)
    {
        // BouncyCastle numbers the bits of the first octet from the most significant one; the package from bit 0 = digitalSignature.
        var bc = new KeyUsage(bcUsage);
        int ours = Asn1Node.Parse(bc.GetDerEncoded()).GetNamedBits();
        Assert.Equal(bc.GetDerEncoded(), Der.NamedBits(ours));
    }

    [Fact]
    public void TimesMatchBouncyCastle()
    {
        var time = new DateTimeOffset(2026, 10, 10, 12, 34, 56, TimeSpan.Zero);
        Assert.Equal(new DerUtcTime(time.UtcDateTime, 2049).GetDerEncoded(), Der.UtcTime(time));
        Assert.Equal(new DerGeneralizedTime(time.UtcDateTime).GetDerEncoded(), Der.GeneralizedTime(time));
        Assert.Equal(time, Asn1Node.Parse(Der.UtcTime(time)).GetTime());
        Assert.Equal(time, Asn1Node.Parse(Der.GeneralizedTime(time)).GetTime());
        Assert.Equal(new DateTimeOffset(1999, 1, 2, 3, 4, 5, TimeSpan.Zero), Asn1Node.Parse(Der.Time(new DateTimeOffset(1999, 1, 2, 3, 4, 5, TimeSpan.Zero))).GetTime());
        Assert.Equal(Asn1Tag.GeneralizedTime, Der.Time(new DateTimeOffset(2050, 1, 1, 0, 0, 0, TimeSpan.Zero))[0]);
    }

    [Fact]
    public void BerIndefiniteLengthAndConstructedStringsAreRead()
    {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "cd" }, INTEGER 5 }
        var stream = new MemoryStream();
        using (var generator = new BerSequenceGenerator(stream))
        {
            generator.AddObject(new BerOctetString([new DerOctetString("ab"u8.ToArray()), new DerOctetString("cd"u8.ToArray())]));
            generator.AddObject(DerInteger.ValueOf(5));
        }
        byte[] ber = stream.ToArray();
        Assert.Equal(0x80, ber[1]); // really indefinite

        Asn1Node node = Asn1Node.Parse(ber);
        Assert.Equal(2, node.Count);
        Assert.Equal("abcd"u8.ToArray(), node[0].GetOctetString());
        Assert.Equal(5, node[1].GetInt32());
        Assert.Equal(ber, node.Encoded.ToArray());
    }

    [Theory]
    [InlineData("30")]             // no length
    [InlineData("3005020101")]     // shorter than its length
    [InlineData("0201")]           // INTEGER without contents
    [InlineData("02010100")]       // trailing byte
    [InlineData("1F0100")]         // high tag number
    [InlineData("3080020101")]     // missing end-of-contents
    [InlineData("0485FFFFFFFFFF")] // length beyond 32 bits
    public void MalformedInputIsRejected(string hex)
    {
        byte[] data = Convert.FromHexString(hex);
        Assert.Throws<InvalidDataException>(() =>
        {
            Asn1Node node = Asn1Node.Parse(data);
            _ = node.IsConstructed ? node.Children.Count : node.GetInteger().Sign;
        });
    }

    [Fact]
    public void DeepNestingIsRejected()
    {
        byte[] data = [0x04, 0x00];
        for (int i = 0; i < 100; i++)
            data = Der.Sequence(data);
        Asn1Node node = Asn1Node.Parse(data);
        Assert.Throws<InvalidDataException>(() =>
        {
            for (int i = 0; i < 100; i++)
                node = node[0];
        });
    }
}
