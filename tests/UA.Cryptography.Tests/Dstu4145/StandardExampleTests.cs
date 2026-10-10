using System.Numerics;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Tests.Dstu4145;

/// <summary>
/// Known-answer tests: the worked examples of Appendix Б of DSTU 4145-2002, checked value by value.
/// </summary>
public class StandardExampleTests
{
    private static BigInteger H(string hex) => Hex.ToBigInteger(hex);

    public sealed record Example(
        string Name,
        Func<BinaryField> Field,
        int A, string B, string N,
        string Px, string Py,
        string D, string Qx, string Qy,
        string Hash, string HElement,
        string E, string EPx, string EPy,
        string Y, string R, string S,
        int SignatureBits, string Signature);

    /// <summary>Б.1: polynomial basis, GF(2^163), x^163 + x^7 + x^6 + x^3 + 1.</summary>
    public static readonly Example B1 = new(
        "Б.1 (PB, m = 163)",
        () => new PolynomialBasisField(163, 3, 6, 7),
        1, "5FF6108462A2DC8210AB403925E638A19C1455D21", "400000000000000000002BEC12BE2262D39BCF14D",
        "72D867F93A93AC27DF9FF01AFFE74885C8C540420", "0224A9C3947852B97C5599D5F4AB81122ADC3FD9B",
        "183F60FDF7951FF47D67193F8D073790C1C9B5A3E",
        // The printed standard misses one digit of x_Q ("...ABD2DA"); see the converter's note in docs.
        "057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA", "3E85444324BCF06AD85ABF6AD7B5F34770532B9AA",
        "09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF",
        "03A2EB95B7180166DDF73532EEB76EDAEF52247FF",
        "1025E40BD97DB012B7A1D79DE8E12932D247F61C6",
        "42A7D756D70E1C9BA62D2CB43707C35204EF3C67C", "5310AE5E560464A95DC80286F17EB762EC544B15B",
        "274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
        "274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
        "2100D86957331832B8E8C230F5BD6A332B3615ACA",
        512,
        "000000000000000000000002100D86957331832B8E8C230F5BD6A332B3615ACA000" +
        "00000000000000000000274EA2C0CAA014A0D80A424F59ADE7A93068D08A7");

    /// <summary>Б.2: optimal normal basis, GF(2^173).</summary>
    public static readonly Example B2 = new(
        "Б.2 (ONB, m = 173)",
        () => new OptimalNormalBasisField(173),
        0, "043D7E139319F43BA00944915740E1E6651B06E278C7", "800000000000000000000189B4E67606E3825BB2831",
        "1D26E5282C2647E1B0327CB4F6087932A0A1F006A89F", "0322218E4551CF8F6E3345644A10B2408F5DF19EC2C7",
        "49FF09C848613AEA23699F78C960D5174617311ADCC",
        "16C1FF796B32D6D2FC83CA9530B368B322F7874B2D01", "1F253334197826B6ADAE44EDEAA7EA281D1C5E597A37",
        "2A681ECE118389B27A108137187EA862117EF1484289470ECAC802C5A651FDA8",
        "0137187EA862117EF1484289470ECAC802C5A651FDA8",
        "70516411E5D9886B8486ECE54A30E9403D103B95F90",
        "028886EA28A7C2951FA6473EB3EBC861D3EDB1FBB031", "19059E90F7C7725079CFFE312A389B265140F5BDA493",
        "0477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
        "477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
        "472EA56AE478F95F1EC9F628FF43857E168B50FB819",
        352,
        "0472EA56AE478F95F1EC9F628FF43857E168B50FB819" +
        "0477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A");

    public static TheoryData<string> Examples => new() { B1.Name, B2.Name };

    private static Example Get(string name) => name == B1.Name ? B1 : B2;

    private static (Dstu4145DomainParameters Parameters, Dstu4145Signer Signer) Setup(Example x)
    {
        BinaryField field = x.Field();
        var curve = new BinaryCurve(field, x.A, H(x.B));
        CurvePoint p = curve.CreatePoint(x.Px, x.Py);
        var parameters = new Dstu4145DomainParameters(curve, p, H(x.N));
        return (parameters, new Dstu4145Signer(parameters));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void BasePointHasOrderN(string name)
    {
        var (parameters, _) = Setup(Get(name));
        Assert.True(parameters.Curve.Multiply(parameters.BasePoint, parameters.N).IsInfinity);
        Assert.Null(parameters.Validate());
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void PublicKey(string name)
    {
        Example x = Get(name);
        var (parameters, signer) = Setup(x);
        CurvePoint q = signer.ComputePublicKey(H(x.D));
        Assert.Equal(H(x.Qx), q.AffineX.ToBigInteger());
        Assert.Equal(H(x.Qy), q.AffineY.ToBigInteger());
        Assert.Null(parameters.ValidatePublicKey(q));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void HashToFieldElement(string name)
    {
        Example x = Get(name);
        var (parameters, _) = Setup(x);
        FieldElement h = Dstu4145Encoding.HashToFieldElement(Hex.ToBytes(x.Hash), parameters.Field);
        Assert.Equal(H(x.HElement), h.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void Presignature(string name)
    {
        Example x = Get(name);
        var (_, signer) = Setup(x);
        Dstu4145Presignature? pre = signer.ComputePresignature(H(x.E));
        Assert.NotNull(pre);
        Assert.Equal(H(x.EPx), pre!.Fe.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void Signature(string name)
    {
        Example x = Get(name);
        var (parameters, signer) = Setup(x);
        FieldElement h = Dstu4145Encoding.HashToFieldElement(Hex.ToBytes(x.Hash), parameters.Field);
        Dstu4145Presignature pre = signer.ComputePresignature(H(x.E))!;

        FieldElement y = h * pre.Fe;
        Assert.Equal(H(x.Y), y.ToBigInteger());

        var (r, s) = signer.Sign(H(x.D), h, pre)!.Value;
        Assert.Equal(H(x.R), r);
        Assert.Equal(H(x.S), s);

        byte[] d = Dstu4145Encoding.EncodeSignature(r, s, x.SignatureBits);
        Assert.Equal(x.Signature, Convert.ToHexString(d));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void Verification(string name)
    {
        Example x = Get(name);
        var (parameters, signer) = Setup(x);
        CurvePoint q = parameters.Curve.CreatePoint(x.Qx, x.Qy);

        // R = sP + rQ must equal eP
        CurvePoint r = parameters.Curve.Multiply(parameters.BasePoint, H(x.S)) + parameters.Curve.Multiply(q, H(x.R));
        Assert.Equal(H(x.EPx), r.AffineX.ToBigInteger());
        Assert.Equal(H(x.EPy), r.AffineY.ToBigInteger());

        Assert.True(signer.VerifyHash(q, Hex.ToBytes(x.Hash), Hex.ToBytes(x.Signature)));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void TamperedSignatureIsRejected(string name)
    {
        Example x = Get(name);
        var (parameters, signer) = Setup(x);
        CurvePoint q = parameters.Curve.CreatePoint(x.Qx, x.Qy);
        byte[] hash = Hex.ToBytes(x.Hash);
        byte[] signature = Hex.ToBytes(x.Signature);

        for (int i = 0; i < signature.Length; i += 7)
        {
            byte[] bad = (byte[])signature.Clone();
            bad[i] ^= 0x10;
            Assert.False(signer.VerifyHash(q, hash, bad), $"byte {i}");
        }

        byte[] badHash = (byte[])hash.Clone();
        badHash[^1] ^= 1;
        Assert.False(signer.VerifyHash(q, badHash, signature));
    }
}
