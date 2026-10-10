namespace UA.Cryptography.Tests.Support;

/// <summary>Committed test data (<c>TestData/</c>, copied next to the test assembly). Everything there is public.</summary>
internal static class TestFiles
{
    public static string Root { get; } = System.IO.Path.Combine(AppContext.BaseDirectory, "TestData");

    public static string Path(params string[] parts) => System.IO.Path.Combine([Root, .. parts]);

    public static byte[] Read(params string[] parts) => File.ReadAllBytes(Path(parts));

    /// <summary>Public certificates of Ukrainian certification authorities, 2005 – 2015 (expired).</summary>
    public static string HistoricalCertificates => Path("certificates", "historical");

    /// <summary>Current self-signed roots of the Central Certification Authority (ЦЗО).</summary>
    public static string CzoRoots => Path("certificates", "czo-roots");

    /// <summary>Public intermediate (issuing) CA certificates that chain to <see cref="CzoRoots"/>.</summary>
    public static string Intermediates => Path("certificates", "intermediates");

    /// <summary>Reference vectors produced by other implementations (see <c>tools/</c>).</summary>
    public static string Vectors => Path("vectors");
}
