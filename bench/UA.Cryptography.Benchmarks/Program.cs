using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Dstu7564;
using UA.Cryptography.Dstu7624;
using UA.Cryptography.Gost;
using UA.Cryptography.Math;

// Simple Stopwatch benchmark: no external dependencies, prints a Markdown table.
// Usage: dotnet run -c Release --project bench/UA.Cryptography.Benchmarks [--portable] [--quick]

bool portable = args.Contains("--portable");
bool quick = args.Contains("--quick");
if (portable)
    Gf2Poly.UseHardware = false;

Console.WriteLine($"# DSTU 4145 benchmark ({RuntimeInformationString()})");
Console.WriteLine();
Console.WriteLine($"Carry-less multiplication: {(Gf2Poly.UseHardware ? "hardware (PMULL/PCLMULQDQ)" : "portable (4-bit window)")}");
Console.WriteLine();
Console.WriteLine("| Curve | mul, ns | sqr, ns | inv, µs | kP, µs | sign, µs | verify, µs |");
Console.WriteLine("|---|---:|---:|---:|---:|---:|---:|");

var curves = new List<(string Name, Dstu4145DomainParameters P)>();
foreach (int m in Dstu4145NamedCurves.PolynomialDegrees)
    curves.Add(($"PB {m}", Dstu4145NamedCurves.Polynomial(m)));
foreach (int m in Dstu4145NamedCurves.NormalDegrees)
    curves.Add(($"ONB {m}", Dstu4145NamedCurves.OptimalNormal(m)));

// Warm-up pass over every curve so that the JIT reaches its final tier before anything is measured.
foreach (var (_, p) in curves)
{
    var warm = new Dstu4145Signer(p);
    Dstu4145KeyPair key = warm.GenerateKeyPair();
    byte[] hash = RandomNumberGenerator.GetBytes(32);
    for (int i = 0; i < (quick ? 3 : 20); i++)
        warm.VerifyHash(key.PublicKey, hash, warm.SignHash(key.PrivateKey, hash));
}

foreach (var (name, p) in curves)
{
    BinaryField f = p.Field;
    var signer = new Dstu4145Signer(p);
    Dstu4145KeyPair key = signer.GenerateKeyPair();
    byte[] hash = RandomNumberGenerator.GetBytes(32);
    byte[] signature = signer.SignHash(key.PrivateKey, hash);

    FieldElement a = f.Random(), b = f.Random();
    var r = new ulong[f.Words];
    double mul = Measure(() => f.Multiply(a.Value, b.Value, r), quick ? 20_000 : 200_000);
    double sqr = Measure(() => f.Square(a.Value, r), quick ? 20_000 : 200_000);
    double inv = Measure(() => f.Invert(a.Value, r), quick ? 500 : 5_000) / 1000;
    BigInteger k = p.RandomInteger();
    double kp = Measure(() => p.Curve.Multiply(p.BasePoint, k), quick ? 20 : 200) / 1000;
    double sign = Measure(() => signer.SignHash(key.PrivateKey, hash), quick ? 20 : 200) / 1000;
    double verify = Measure(() => signer.VerifyHash(key.PublicKey, hash, signature), quick ? 20 : 200) / 1000;
    Console.WriteLine($"| {name} | {mul:F0} | {sqr:F0} | {inv:F1} | {kp:F0} | {sign:F0} | {verify:F0} |");
}

Console.WriteLine();
Console.WriteLine("| Hash | MB/s |");
Console.WriteLine("|---|---:|");
var payload = RandomNumberGenerator.GetBytes(1 << 20);
foreach (var (name, hash) in new (string, System.Security.Cryptography.HashAlgorithm)[]
         {
             ("GOST 34.311", new Gost34311()),
             ("DSTU 7564-256", new Dstu7564Hash(256)),
             ("DSTU 7564-512", new Dstu7564Hash(512)),
         })
{
    double ns = Measure(() => hash.ComputeHash(payload), quick ? 3 : 20);
    Console.WriteLine($"| {name} | {payload.Length / (ns / 1e9) / 1e6:F0} |");
}

Console.WriteLine();
Console.WriteLine("| DSTU 7624 (Kalyna) | MB/s |");
Console.WriteLine("|---|---:|");
foreach (var (block, keyBits) in new[] { (128, 128), (128, 256), (256, 256), (256, 512), (512, 512) })
{
    byte[] key = RandomNumberGenerator.GetBytes(keyBits / 8), iv = RandomNumberGenerator.GetBytes(block / 8);
    var ecb = new Dstu7624Ecb(block, key);
    var gcm = new Dstu7624Gcm(block, key);
    double ecbNs = Measure(() => ecb.Encrypt(payload), quick ? 3 : 10);
    double gcmNs = Measure(() => gcm.Encrypt(iv, ReadOnlySpan<byte>.Empty, payload, block), quick ? 3 : 10);
    Console.WriteLine($"| ECB {block}/{keyBits} | {payload.Length / (ecbNs / 1e9) / 1e6:F0} |");
    Console.WriteLine($"| GCM {block}/{keyBits} | {payload.Length / (gcmNs / 1e9) / 1e6:F0} |");
}

static double Measure(Action action, int iterations)
{
    for (int i = 0; i < System.Math.Max(3, iterations / 10); i++)
        action(); // warm-up, JIT tiering
    var sw = Stopwatch.StartNew();
    for (int i = 0; i < iterations; i++)
        action();
    sw.Stop();
    return sw.Elapsed.TotalMilliseconds * 1e6 / iterations; // ns per call
}

static string RuntimeInformationString() =>
    $"{System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}, " +
    $"{System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}, " +
    $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription}";
