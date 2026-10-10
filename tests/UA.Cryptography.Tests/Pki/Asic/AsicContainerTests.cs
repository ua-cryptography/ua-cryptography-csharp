using System.IO.Compression;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Asic;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.Xades;
using CadesOptions = UA.Cryptography.Pki.Cades.CadesOptions;
using Oids = UA.Cryptography.Tests.Support.Oids;

namespace UA.Cryptography.Tests.Pki.Asic;

/// <summary>
/// ASiC-S and ASiC-E made by the package pass the structural checks of the tests (<see cref="Zip.ReadContainer"/>) and
/// the package's verifier; the containers of the test builders verify too; unsigned or replaced entries are caught.
/// </summary>
public class AsicContainerTests
{
    private static readonly SignedFile[] Files = [new("contract.pdf", "%PDF-1.7 fake"u8.ToArray()), new("annex/табл.csv", "a;b\n1;2"u8.ToArray())];

    private static ValidationOptions Trusting(Hierarchy pki) => new() { TrustAnchors = [PkiLayer.Root(pki)], ExtraCertificates = PkiLayer.AllCertificates(pki) };

    [Fact]
    public void PackageAsicSIsWellFormedAndVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] cades = new CadesSigner(PkiLayer.Signer(pki), PkiLayer.Services(pki)).Sign(Files[0].Content,
            new CadesOptions(Oids.Gost34311, Detached: true, SignatureLevel.T));
        byte[] container = AsicContainer.CreateAsicS(Files[0].Name, Files[0].Content, cades);

        Dictionary<string, byte[]> entries = Zip.ReadContainer(container, CadesBuilder.AsicSMimeType);
        Assert.Equal(["mimetype", "contract.pdf", CadesBuilder.AsicSSignatureEntry], entries.Keys);

        VerificationResult result = SignatureVerifier.Verify(container, _ => null, Trusting(pki));
        Assert.True(result.IsValid, Cades.CadesSignerTests.Describe(result));
        Assert.Equal("ASiC-S", result.Format);
        Assert.Equal(Files[0].Content, result.SignedFiles["contract.pdf"]);
    }

    [Fact]
    public void PackageAsicEIsWellFormedAndVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        var signature = new XadesSigner(PkiLayer.Signer(pki), PkiLayer.Services(pki)).Sign(Files, Oids.Dstu7564_256, SignatureLevel.LT);
        byte[] container = AsicContainer.CreateAsicE(Files, signature);

        Dictionary<string, byte[]> entries = Zip.ReadContainer(container, XadesBuilder.AsicEMimeType);
        Assert.Contains("META-INF/manifest.xml", entries.Keys);
        Assert.Contains("META-INF/signatures001.xml", entries.Keys);

        VerificationResult result = SignatureVerifier.Verify(container, _ => null, Trusting(pki));
        Assert.True(result.IsValid, Cades.CadesSignerTests.Describe(result));
        Assert.Equal("ASiC-E", result.Format);
        Assert.Equal(2, result.SignedFiles.Count);
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "manifest" && c.Status == CheckStatus.Passed);
    }

    [Fact]
    public void TestBuilderContainersVerify()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] data = "test"u8.ToArray();
        byte[] asice = XadesBuilder.WrapAsicE("data.txt", data, XadesBuilder.Build(data, "data.txt", pki, Oids.Dstu7564_256));
        byte[] asics = CadesBuilder.WrapAsicS("data.txt", data,
            CadesBuilder.Build(data, pki, new Support.CadesOptions(Oids.Gost34311, Enveloped: false, CadesLevel.T, ContentTimeStamp: true)));
        Assert.True(SignatureVerifier.Verify(asice, _ => null, Trusting(pki)).IsValid);
        Assert.True(SignatureVerifier.Verify(asics, _ => null, Trusting(pki)).IsValid);
    }

    [Fact]
    public void AddedOrReplacedEntriesAreCaught()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] container = AsicContainer.CreateAsicE(Files, new XadesSigner(PkiLayer.Signer(pki)).Sign(Files));

        byte[] added = Rewrite(container, zip => Write(zip, "unsigned.txt", "not signed"u8.ToArray()));
        VerificationResult result = SignatureVerifier.Verify(added, _ => null, Trusting(pki));
        Assert.False(result.IsValid);
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "file 'unsigned.txt'" && c.Status == CheckStatus.Failed);

        byte[] replaced = Rewrite(container, zip =>
        {
            zip.GetEntry("contract.pdf")!.Delete();
            Write(zip, "contract.pdf", "%PDF-1.7 forged"u8.ToArray());
        });
        result = SignatureVerifier.Verify(replaced, _ => null, Trusting(pki));
        Assert.False(result.IsValid);
        Assert.Contains(result.Signatures[1].Checks, c => c.Name == "reference 'contract.pdf'" && c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void WrongMimeTypeIsReported()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] container = AsicContainer.CreateAsicE(Files, new XadesSigner(PkiLayer.Signer(pki)).Sign(Files));
        byte[] wrong = Rewrite(container, zip =>
        {
            zip.GetEntry("mimetype")!.Delete();
            Write(zip, "mimetype", "application/zip"u8.ToArray());
        });
        VerificationResult result = SignatureVerifier.Verify(wrong, _ => null, Trusting(pki));
        Assert.False(result.IsValid);
        Assert.Contains(result.Signatures[0].Checks, c => c.Name == "mimetype" && c.Status == CheckStatus.Failed);
    }

    private static byte[] Rewrite(byte[] container, Action<ZipArchive> change)
    {
        var buffer = new MemoryStream();
        buffer.Write(container);
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Update, leaveOpen: true))
            change(zip);
        return buffer.ToArray();
    }

    private static void Write(ZipArchive zip, string name, byte[] content)
    {
        using Stream s = zip.CreateEntry(name).Open();
        s.Write(content);
    }
}
