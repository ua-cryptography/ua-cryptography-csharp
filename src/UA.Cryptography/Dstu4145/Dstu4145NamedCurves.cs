using UA.Cryptography.EC;
using UA.Cryptography.Math;

namespace UA.Cryptography.Dstu4145;

/// <summary>
/// Recommended fields and curves of DSTU 4145-2002 (table 1, table 2, Appendix Г) with base points.
/// </summary>
/// <remarks>
/// <para>
/// The standard itself lists only (A, B, n); base points are to be computed by 7.3. The base points below are the
/// ones published by the original cryptography.org.ua project (2010, "Рекомендованные кривые", tables 2.1 and 2.2);
/// the polynomial-basis ones coincide with BouncyCastle's <c>DSTU4145NamedCurves</c>, and the tests check every one
/// of them (on the curve, nP = O, section 8).
/// </para>
/// <para>
/// For the optimal normal basis with m = 179, 191 and 431 those tables list a coefficient B' that differs from
/// table Г.2: B' = B^(2^j) (a cyclic shift of B, j = 94, 190, 234), i.e. their curve is the image of the
/// standard curve under a power of the Frobenius map. Both curves are isomorphic and have the same order. This class
/// uses B exactly as in table Г.2 and maps the published base point back, (x, y) → (x^(2^-j), y^(2^-j)).
/// </para>
/// </remarks>
public static class Dstu4145NamedCurves
{
    /// <summary>Recommended primitive polynomials of table 1: m → (k, j, l), j = l = 0 for trinomials.</summary>
    public static readonly IReadOnlyDictionary<int, (int K, int J, int L)> PolynomialTable = new Dictionary<int, (int, int, int)>
    {
        [163] = (3, 6, 7), [167] = (6, 0, 0), [173] = (1, 2, 10), [179] = (1, 2, 4), [181] = (1, 6, 7),
        [191] = (9, 0, 0), [193] = (15, 0, 0), [197] = (1, 2, 21), [199] = (1, 2, 11), [211] = (1, 6, 12),
        [223] = (1, 2, 12), [227] = (1, 2, 21), [229] = (1, 2, 21), [233] = (1, 4, 9), [239] = (1, 2, 15),
        [241] = (1, 4, 15), [251] = (1, 4, 14), [257] = (12, 0, 0), [263] = (1, 2, 27), [269] = (1, 6, 7),
        [271] = (1, 3, 16), [277] = (2, 3, 23), [281] = (1, 4, 9), [283] = (1, 9, 26), [293] = (1, 6, 11),
        [307] = (2, 4, 8), [311] = (1, 4, 29), [313] = (1, 3, 7), [317] = (2, 5, 9), [331] = (2, 5, 12),
        [337] = (1, 6, 10), [347] = (1, 6, 17), [349] = (2, 5, 6), [353] = (3, 7, 26), [359] = (2, 4, 18),
        [367] = (21, 0, 0), [373] = (1, 6, 9), [379] = (1, 6, 17), [383] = (1, 5, 9), [389] = (1, 10, 17),
        [397] = (1, 3, 22), [401] = (1, 4, 29), [409] = (1, 6, 15), [419] = (1, 14, 21), [421] = (1, 4, 7),
        [431] = (1, 3, 5), [433] = (1, 5, 15), [439] = (2, 3, 8), [443] = (1, 3, 28), [449] = (3, 5, 25),
        [457] = (16, 0, 0), [461] = (1, 4, 23), [463] = (1, 3, 24), [467] = (1, 3, 28), [479] = (1, 6, 25),
        [487] = (1, 2, 15), [491] = (2, 6, 17), [499] = (2, 6, 29), [503] = (3, 0, 0), [509] = (2, 3, 23),
    };

    /// <summary>Creates GF(2^m) with the recommended polynomial of table 1.</summary>
    public static PolynomialBasisField CreatePolynomialBasisField(int m)
    {
        if (!PolynomialTable.TryGetValue(m, out var p))
            throw new ArgumentException($"m = {m} is not listed in table 1.", nameof(m));
        return new PolynomialBasisField(m, p.K, p.J, p.L);
    }

    private sealed record Spec(int M, int A, string B, string N, string X, string Y);

    // Table Г.1 + the published base points (table 2.1).
    private static readonly Spec[] PolynomialSpecs =
    {
        new(163, 1, "5FF6108462A2DC8210AB403925E638A19C1455D21", "400000000000000000002BEC12BE2262D39BCF14D",
            "2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE", "3826F008A8C51D7B95284D9D03FF0E00CE2CD723A"),
        new(167, 1, "6EE3CEEB230811759F20518A0930F1A4315A827DAC", "3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F",
            "7A1F6653786A68192803910A3D30B2A2018B21CD54", "5F49EB26781C0EC6B8909156D98ED435E45FD59918"),
        new(173, 0, "108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", "800000000000000000000189B4E67606E3825BB2831",
            "4D41A619BCC6EADF0448FA22FAD567A9181D37389CA", "10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1"),
        new(179, 1, "4A6E0856526436F2F88DD07A341E32D04184572BEB710", "3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF",
            "6BA06FE51464B2BD26DC57F48819BA9954667022C7D03", "25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E"),
        new(191, 1, "7BC86E2102902EC4D5890E8B6B4981FF27E0482750FEFC03", "40000000000000000000000069A779CAC1DABC6788F7474F",
            "714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129", "29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA"),
        new(233, 1, "06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C",
            "1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
            "3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96",
            "9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35"),
        new(257, 0, "1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10",
            "800000000000000000000000000000006759213AF182E987D3E17714907D470D",
            "02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7",
            "10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF"),
        new(307, 1, "393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB",
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7",
            "216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA",
            "5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0"),
        new(367, 1, "43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136",
            "40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49",
            "324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1",
            "1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10"),
        new(431, 1, "03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3",
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
            "1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D",
            "70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9"),
    };

    // Table Г.2 + the published base points (table 2.2, mapped by Frobenius for 179, 191, 431, see remarks).
    private static readonly Spec[] NormalSpecs =
    {
        new(173, 0, "043D7E139319F43BA00944915740E1E6651B06E278C7", "800000000000000000000189B4E67606E3825BB2831",
            "0A3B8B8D704089B24318CAA51917CB6E424B4E6DEA56", "005A43D5EE1F400349CF35150C74F119A39145F0CB08"),
        new(179, 1, "0B151F20BCB9AC860B2F2CCE4F5E27EC1840C9E9D30BB", "3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF",
            "0E6F12B12B790EC86D9AE48FA089132A0823B8ACF069F", "16472C99B8A067B960ACF1652F859A630D4310B789BB3"),
        new(191, 1, "09C38E4E94EB67753A07EABA227B97EDD72ACE09D0F18F7C", "40000000000000000000000069A779CAC1DABC6788F7474F",
            "78ACF069F1CDE256256F21D90DB35CA795792D5F758EC2E9", "2BF22EAA35F3100F4B82F014A9AE804E98FA8EC0F0C1135F"),
        new(233, 1, "080F920952A702C75B704A424C018EEA55AA44664F3A003E0962D4F9A8E",
            "1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
            "0A0823B8ACF069F1CDE256256F21D90DB35CA795792D5F758EC2E9992FB",
            "19DAE222AF326D33AFB7761953F624A23D3EB1CA7A1C300F0AA9953CA85"),
        new(431, 1, "19794FD03E5CFCBC1B17A03BF8ED0D946F57FE2C1AE97E4A669FDBD7BDA20380053791356B5D6941BC3235EC1F8FCA04085260CA9B77",
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
            "2ED60508C991230234FB8F85F902E0D74C24373EE9F16B7A990100C167E6BE3920ABD9B1EA55FEA60B128BB9E2CAEA72E442B97D4EAF",
            "40E90CA4A61560A375FC85C53E0DF8466811261FC00442B6B4C70DB77D94777C50FCE0C2CF6ABE3A653A3F270D3014A6002E8C907404"),
    };

    private static readonly Lazy<Dstu4145DomainParameters>[] PolynomialCurves =
        PolynomialSpecs.Select(s => new Lazy<Dstu4145DomainParameters>(() => Build(s, CreatePolynomialBasisField(s.M)))).ToArray();

    private static readonly Lazy<Dstu4145DomainParameters>[] NormalCurves =
        NormalSpecs.Select(s => new Lazy<Dstu4145DomainParameters>(() => Build(s, new OptimalNormalBasisField(s.M)))).ToArray();

    /// <summary>Degrees of the curves of table Г.1.</summary>
    public static IReadOnlyList<int> PolynomialDegrees { get; } = PolynomialSpecs.Select(s => s.M).ToArray();

    /// <summary>Degrees of the curves of table Г.2.</summary>
    public static IReadOnlyList<int> NormalDegrees { get; } = NormalSpecs.Select(s => s.M).ToArray();

    /// <summary>Curve of table Г.1 (polynomial basis) over GF(2^m).</summary>
    public static Dstu4145DomainParameters Polynomial(int m) => Find(PolynomialSpecs, PolynomialCurves, m, "Г.1");

    /// <summary>Curve of table Г.2 (optimal normal basis) over GF(2^m).</summary>
    public static Dstu4145DomainParameters OptimalNormal(int m) => Find(NormalSpecs, NormalCurves, m, "Г.2");

    private static Dstu4145DomainParameters Find(Spec[] specs, Lazy<Dstu4145DomainParameters>[] curves, int m, string table)
    {
        int i = Array.FindIndex(specs, s => s.M == m);
        if (i < 0)
            throw new ArgumentException($"Table {table} has no curve over GF(2^{m}).", nameof(m));
        return curves[i].Value;
    }

    private static Dstu4145DomainParameters Build(Spec s, BinaryField field)
    {
        var curve = new BinaryCurve(field, s.A, Hex.ToBigInteger(s.B));
        return new Dstu4145DomainParameters(curve, curve.CreatePoint(s.X, s.Y), Hex.ToBigInteger(s.N));
    }
}
