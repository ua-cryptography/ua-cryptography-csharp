using UA.Cryptography.Dstu4145;

namespace UA.Cryptography.Tests.Support;

/// <summary>Theory data over the 15 recommended curves of Appendix Г: (basis, m), basis "PB" (Г.1) or "ONB" (Г.2).</summary>
public static class RecommendedCurves
{
    public static TheoryData<string, int> All()
    {
        var data = new TheoryData<string, int>();
        foreach (int m in Dstu4145NamedCurves.PolynomialDegrees)
            data.Add("PB", m);
        foreach (int m in Dstu4145NamedCurves.NormalDegrees)
            data.Add("ONB", m);
        return data;
    }

    internal static Dstu4145DomainParameters Get(string basis, int m) =>
        basis == "PB" ? Dstu4145NamedCurves.Polynomial(m) : Dstu4145NamedCurves.OptimalNormal(m);
}
