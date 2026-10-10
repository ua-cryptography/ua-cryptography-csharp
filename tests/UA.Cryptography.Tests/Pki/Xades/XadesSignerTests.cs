using System.Text;
using System.Xml;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.Xades;
using UA.Cryptography.Pki.Xml;
using Oids = UA.Cryptography.Tests.Support.Oids;
using SignatureLevel = UA.Cryptography.Pki.SignatureLevel;

namespace UA.Cryptography.Tests.Pki.Xades;

/// <summary>
/// XAdES made by the package and checked with Microsoft's canonicalization and the BouncyCastle-based recipes of
/// <see cref="UaPki"/>; XAdES made by the test builder (<see cref="XadesBuilder"/>) checked by the package's verifier;
/// tampering and signature wrapping.
/// </summary>
public class XadesSignerTests
{
    private const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private static readonly SignedFile File1 = new("заява.txt", "Текст заяви"u8.ToArray());
    private static readonly SignedFile File2 = new("data file.bin", [0, 1, 2, 3, 255]);

    private static ValidationOptions Trusting(Hierarchy pki) => new() { TrustAnchors = [PkiLayer.Root(pki)], ExtraCertificates = PkiLayer.AllCertificates(pki) };

    private static XmlDocument Sign(string hashOid, SignatureLevel level, params SignedFile[] files)
    {
        byte[] xml = new XadesSigner(PkiLayer.Signer(Hierarchy.Shared), PkiLayer.Services(Hierarchy.Shared)).SignToBytes(files, hashOid, level);
        return XmlSafe.Load(xml); // as received: parsed from bytes
    }

    private static byte[]? Resolve(string name, params SignedFile[] files) => files.FirstOrDefault(f => f.Name == name)?.Content;

    private static XmlNamespaceManager Ns(XmlDocument document)
    {
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("ds", Ds);
        ns.AddNamespace("xades", XadesNs);
        return ns;
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void PackageSignatureVerifiesWithMicrosoftCanonicalization(string hashOid)
    {
        XmlDocument document = Sign(hashOid, SignatureLevel.B, File1, File2);
        XmlNamespaceManager ns = Ns(document);
        var certificate = UaPki.ParseCertificate(Convert.FromBase64String(document.SelectSingleNode("//ds:X509Certificate", ns)!.InnerText));
        var (parameters, publicKey, _) = UaPki.ReadPublicKey(certificate);

        // Each reference digest, recomputed with Microsoft's exclusive C14N for the signed properties.
        foreach (XmlElement reference in document.SelectNodes("//ds:SignedInfo/ds:Reference", ns)!.Cast<XmlElement>())
        {
            string uri = reference.GetAttribute("URI");
            byte[] content = uri.StartsWith('#')
                ? XadesBuilder.Canonicalize((XmlElement)document.SelectSingleNode($"//*[@Id='{uri[1..]}']")!)
                : Resolve(Uri.UnescapeDataString(uri), File1, File2)!;
            Assert.Equal(Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText), UaPki.Hash(hashOid, content));
        }
        Assert.Contains(document.SelectNodes("//ds:Reference/@URI", ns)!.Cast<XmlAttribute>(), a => a.Value == "data%20file.bin");

        byte[] signedInfo = XadesBuilder.Canonicalize((XmlElement)document.SelectSingleNode("//ds:SignedInfo", ns)!);
        byte[] value = Convert.FromBase64String(document.SelectSingleNode("//ds:SignatureValue", ns)!.InnerText);
        Assert.True(UaPki.VerifyDstu4145(parameters, publicKey, UaPki.Hash(hashOid, signedInfo), value));
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256, SignatureLevel.B)]
    [InlineData(Oids.Dstu7564_256, SignatureLevel.T)]
    [InlineData(Oids.Dstu7564_256, SignatureLevel.LT)]
    [InlineData(Oids.Gost34311, SignatureLevel.LT)]
    public void PackageSignatureVerifiesByThePackage(string hashOid, SignatureLevel level)
    {
        Hierarchy pki = Hierarchy.Shared;
        XmlDocument document = Sign(hashOid, level, File1, File2);
        VerificationReport report = Assert.Single(XadesVerifier.Verify(document, n => Resolve(n, File1, File2), Trusting(pki)));
        Assert.True(report.IsValid, string.Join("\n", report.Checks.Select(c => $"{c.Status} {c.Name}: {c.Details}")));
        Assert.Equal(level >= SignatureLevel.T, report.TimeStampTime is not null);
        Assert.Equal($"XAdES-B-{level}", report.Format!.Split(',')[0]);
        if (level == SignatureLevel.LT)
        {
            Assert.DoesNotContain(report.Checks, c => c.Name.StartsWith("signer:", StringComparison.Ordinal) && c.Status != CheckStatus.Passed);

            // The time-stamp is a BouncyCastle-readable token over the canonical ds:SignatureValue.
            XmlNamespaceManager ns = Ns(document);
            var token = new CmsSignedData(Convert.FromBase64String(document.SelectSingleNode("//xades:EncapsulatedTimeStamp", ns)!.InnerText));
            Assert.True(UaPki.ImprintCovers(UaPki.ReadTimeStamp(token), XadesBuilder.Canonicalize((XmlElement)document.SelectSingleNode("//ds:SignatureValue", ns)!)));
            foreach (XmlElement ocsp in document.SelectNodes("//xades:EncapsulatedOCSPValue", ns)!.Cast<XmlElement>())
            {
                var response = UaPki.ReadOcspResponse(Convert.FromBase64String(ocsp.InnerText));
                Assert.True(UaPki.VerifyOcsp(response, UaPki.FindOcspResponder(response, [pki.Signer.Certificate, .. pki.ValidationCertificates])));
            }
        }
    }

    [Theory]
    [InlineData(Oids.Dstu7564_256, XadesLevel.B)]
    [InlineData(Oids.Gost34311, XadesLevel.T)]
    [InlineData(Oids.Dstu7564_256, XadesLevel.LT)]
    public void TestBuilderSignatureVerifiesByThePackage(string hashOid, XadesLevel level)
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] data = "test"u8.ToArray();
        XmlDocument document = XmlSafe.Load(Encoding.UTF8.GetBytes(XadesBuilder.Build(data, "data.txt", pki, hashOid, level).OuterXml));
        VerificationReport report = Assert.Single(XadesVerifier.Verify(document, n => n == "data.txt" ? data : null, Trusting(pki)));
        Assert.True(report.IsValid, string.Join("\n", report.Checks.Select(c => $"{c.Status} {c.Name}: {c.Details}")));
        if (level == XadesLevel.LT)
            Assert.Equal(2, report.Checks.Count(c => c.Name.StartsWith("signer: revocation", StringComparison.Ordinal) && c.Status == CheckStatus.Passed));
    }

    [Fact]
    public void TamperedFileFailsItsReference()
    {
        XmlDocument document = Sign(Oids.Dstu7564_256, SignatureLevel.B, File1, File2);
        VerificationReport report = XadesVerifier.Verify(document, n => n == File2.Name ? [0, 1, 2, 3, 254] : Resolve(n, File1), new ValidationOptions())[0];
        Assert.False(report.IsValid);
        Assert.Contains(report.Checks, c => c.Name == "reference 'data%20file.bin'" && c.Status == CheckStatus.Failed);
        Assert.Contains(report.Checks, c => c.Name == $"reference '{Uri.EscapeDataString(File1.Name)}'" && c.Status == CheckStatus.Passed);
    }

    [Fact]
    public void ChangedSignedPropertyOrSignatureValueFails()
    {
        XmlDocument document = Sign(Oids.Dstu7564_256, SignatureLevel.B, File1);
        XmlNamespaceManager ns = Ns(document);
        XmlNode time = document.SelectSingleNode("//xades:SigningTime", ns)!;
        time.InnerText = "2001-01-01T00:00:00Z";
        VerificationReport report = XadesVerifier.Verify(document, n => Resolve(n, File1), new ValidationOptions())[0];
        Assert.Contains(report.Checks, c => c.Name.EndsWith("-SignedProperties'", StringComparison.Ordinal) && c.Status == CheckStatus.Failed);

        document = Sign(Oids.Dstu7564_256, SignatureLevel.B, File1);
        XmlNode value = document.SelectSingleNode("//ds:SignatureValue", Ns(document))!;
        byte[] d = Convert.FromBase64String(value.InnerText);
        d[7] ^= 1;
        value.InnerText = Convert.ToBase64String(d);
        report = XadesVerifier.Verify(document, n => Resolve(n, File1), new ValidationOptions())[0];
        Assert.Contains(report.Checks, c => c.Name == "signature" && c.Status == CheckStatus.Failed);
    }

    /// <summary>
    /// Signature wrapping: a second element with the Id of the signed properties (carrying a forged signing time) must
    /// not be accepted as the covered one.
    /// </summary>
    [Fact]
    public void DuplicateIdIsRejected()
    {
        XmlDocument document = Sign(Oids.Dstu7564_256, SignatureLevel.B, File1);
        XmlNamespaceManager ns = Ns(document);
        var properties = (XmlElement)document.SelectSingleNode("//xades:SignedProperties", ns)!;
        var copy = (XmlElement)properties.CloneNode(deep: true);
        copy.SelectSingleNode("xades:SignedSignatureProperties/xades:SigningTime", ns)!.InnerText = "2001-01-01T00:00:00Z";
        document.DocumentElement!.AppendChild(document.CreateElement("ds", "Object", Ds))!.AppendChild(copy);

        VerificationReport report = XadesVerifier.Verify(document, n => Resolve(n, File1), new ValidationOptions())[0];
        Assert.False(report.IsValid);
        Assert.Contains(report.Checks, c => c.Name == "structure" && c.Details.Contains("Several elements", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingFileIsReported()
    {
        XmlDocument document = Sign(Oids.Dstu7564_256, SignatureLevel.B, File1);
        VerificationReport report = XadesVerifier.Verify(document, _ => null, new ValidationOptions())[0];
        Assert.Contains(report.Checks, c => c.Details == "the referenced file was not given" && c.Status == CheckStatus.Failed);
    }
}
