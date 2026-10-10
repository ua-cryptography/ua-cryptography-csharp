using System.Text;
using System.Xml;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Cms;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Signatures;

/// <summary>
/// XAdES signatures made with the synthetic <see cref="Hierarchy"/> — as a detached XML next to the data and inside an
/// ASiC-E container — and checked by the recipe of docs/signature-formats.md, sections 7 and 8: every ds:Reference
/// digest, the signing certificate digest, the DSTU 4145 signature over the canonical ds:SignedInfo, the signature
/// time-stamp and the long-term validation values.
/// </summary>
public class XadesTests
{
    private const string DataName = "data.txt";
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("test");

    public static TheoryData<string, bool> Variants => new()
    {
        { Oids.Dstu7564_256, false },
        { Oids.Gost34311, false },
        { Oids.Dstu7564_256, true },
    };

    /// <summary>The signature document and a resolver for the detached content its references name.</summary>
    private sealed record XadesFile(XmlDocument Document, XmlNamespaceManager Ns, Func<string, byte[]> ReadDetached)
    {
        public XmlElement Single(string xpath) =>
            (XmlElement?)Document.SelectSingleNode(xpath, Ns) ?? throw new InvalidDataException($"{xpath} not found");

        public IEnumerable<XmlElement> All(string xpath) => Document.SelectNodes(xpath, Ns)!.Cast<XmlElement>();

        public X509Certificate SignerCertificate =>
            UaPki.ParseCertificate(Convert.FromBase64String(Single("//ds:KeyInfo/ds:X509Data/ds:X509Certificate").InnerText));

        public IEnumerable<X509Certificate> CertificateValues =>
            All("//xades:CertificateValues/xades:EncapsulatedX509Certificate").Select(e => UaPki.ParseCertificate(Convert.FromBase64String(e.InnerText)));
    }

    private static XadesFile Create(string hashOid, bool asicE, XadesLevel level = XadesLevel.LT)
    {
        XmlDocument signature = XadesBuilder.Build(Data, DataName, Hierarchy.Shared, hashOid, level);
        return asicE ? LoadAsicE(XadesBuilder.WrapAsicE(DataName, Data, signature)) : LoadDetached(signature.OuterXml);
    }

    /// <summary>A detached XML signature as received: parsed from text, the data file lying next to it.</summary>
    private static XadesFile LoadDetached(string xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        return Open(doc, uri => uri == DataName ? Data : throw new FileNotFoundException(uri));
    }

    /// <summary>An ASiC-E container: structure, manifest, then the signature with references into the archive.</summary>
    private static XadesFile LoadAsicE(byte[] container)
    {
        Dictionary<string, byte[]> entries = Zip.ReadContainer(container, XadesBuilder.AsicEMimeType);

        // The manifest lists the container itself and every data file.
        var manifest = new XmlDocument();
        manifest.Load(new MemoryStream(entries["META-INF/manifest.xml"]));
        List<string> listed = manifest.DocumentElement!.ChildNodes.OfType<XmlElement>()
            .Select(e => e.GetAttribute("full-path", XadesBuilder.Manifest)).ToList();
        Assert.Contains("/", listed);
        Assert.All(entries.Keys.Where(n => n != "mimetype" && !n.StartsWith("META-INF/", StringComparison.Ordinal)),
            f => Assert.Contains(f, listed));

        string signatureEntry = Assert.Single(entries.Keys, n => n.StartsWith("META-INF/signatures", StringComparison.Ordinal) && n.EndsWith(".xml", StringComparison.Ordinal));
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(entries[signatureEntry]));
        Assert.Equal("XAdESSignatures", doc.DocumentElement!.LocalName);
        Assert.Equal(XadesBuilder.Asic, doc.DocumentElement.NamespaceURI);
        return Open(doc, uri => entries.TryGetValue(uri, out byte[]? data) ? data : throw new FileNotFoundException(uri));
    }

    private static XadesFile Open(XmlDocument doc, Func<string, byte[]> readDetached)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XadesBuilder.Ds);
        ns.AddNamespace("xades", XadesBuilder.Xades);
        Assert.Single(doc.SelectNodes("//ds:Signature", ns)!.Cast<XmlNode>());
        return new XadesFile(doc, ns, readDetached);
    }

    private static byte[] Hash(XmlElement withDigestMethod, XadesFile x, byte[] data) =>
        UaPki.Hash(XadesBuilder.HashOf(((XmlElement)withDigestMethod.SelectSingleNode("ds:DigestMethod", x.Ns)!).GetAttribute("Algorithm")), data);

    [Theory]
    [MemberData(nameof(Variants))]
    public void SignatureVerifies(string hashOid, bool asicE)
    {
        XadesFile x = Create(hashOid, asicE);
        string signatureMethod = x.Single("//ds:SignedInfo/ds:SignatureMethod").GetAttribute("Algorithm");
        Assert.Equal(XadesBuilder.SignatureMethod(hashOid), signatureMethod);
        string signatureHash = XadesBuilder.HashOf(signatureMethod);

        X509Certificate certificate = x.SignerCertificate;
        var (parameters, publicKey, _) = UaPki.ReadPublicKey(certificate);

        // Every reference: the detached data file and the signed properties. XML digests keep the hash bytes as they are.
        foreach (XmlElement reference in x.All("//ds:SignedInfo/ds:Reference"))
        {
            string uri = reference.GetAttribute("URI");
            byte[] content = uri.StartsWith('#') ? XadesBuilder.Canonicalize(x.Single($"//*[@Id='{uri[1..]}']")) : x.ReadDetached(uri);
            byte[] expected = Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", x.Ns)!.InnerText);
            Assert.Equal(expected, Hash(reference, x, content));
        }

        // The signed properties bind the signature to this very certificate.
        XmlElement certDigest = x.Single("//xades:SigningCertificateV2/xades:Cert/xades:CertDigest");
        Assert.Equal(Convert.FromBase64String(certDigest.SelectSingleNode("ds:DigestValue", x.Ns)!.InnerText),
            Hash(certDigest, x, certificate.GetEncoded()));

        // The signature itself, over the canonical SignedInfo.
        byte[] signedInfo = XadesBuilder.Canonicalize(x.Single("//ds:SignedInfo"));
        byte[] signatureValue = Convert.FromBase64String(x.Single("//ds:SignatureValue").InnerText);
        Assert.Equal(64, signatureValue.Length); // m = 257: r and s of 32 bytes each
        Assert.True(UaPki.VerifyDstu4145(parameters, publicKey, UaPki.Hash(signatureHash, signedInfo), signatureValue));

        // A single changed byte of the signed data or of the signature breaks it.
        signedInfo[signedInfo.Length / 2] ^= 1;
        Assert.False(UaPki.VerifyDstu4145(parameters, publicKey, UaPki.Hash(signatureHash, signedInfo), signatureValue));
        signatureValue[5] ^= 1;
        byte[] original = UaPki.Hash(signatureHash, XadesBuilder.Canonicalize(x.Single("//ds:SignedInfo")));
        Assert.False(UaPki.VerifyDstu4145(parameters, publicKey, original, signatureValue));
    }

    [Fact]
    public void TamperedDataBreaksTheReference()
    {
        XadesFile x = Create(Oids.Dstu7564_256, asicE: false, XadesLevel.B);
        XmlElement reference = x.All("//ds:SignedInfo/ds:Reference").First(r => r.GetAttribute("URI") == DataName);
        byte[] expected = Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", x.Ns)!.InnerText);
        Assert.NotEqual(expected, Hash(reference, x, Encoding.UTF8.GetBytes("tesT")));
    }

    [Fact]
    public void SignerCertificateIsIssuedByEmbeddedCa()
    {
        XadesFile x = Create(Oids.Dstu7564_256, asicE: false);
        X509Certificate certificate = x.SignerCertificate;
        X509Certificate issuer = Assert.Single(x.CertificateValues, c => c.SubjectDN.Equivalent(certificate.IssuerDN));
        Assert.True(UaPki.VerifyCertificate(certificate, issuer));
        Assert.True(UaPki.ChainsToTrusted(certificate, x.CertificateValues.ToList(), [Hierarchy.Shared.Root.Certificate]));
    }

    /// <summary>XAdES-T: the time-stamp's message imprint is the hash of the canonical ds:SignatureValue element.</summary>
    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void TimeStampCoversTheSignature(string hashOid)
    {
        XadesFile x = Create(hashOid, asicE: false, XadesLevel.T);
        Assert.Empty(x.All("//xades:CertificateValues"));

        var token = new CmsSignedData(Convert.FromBase64String(x.Single("//xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp").InnerText));
        TstInfo info = UaPki.ReadTimeStamp(token);
        Assert.True(UaPki.ImprintCovers(info, XadesBuilder.Canonicalize(x.Single("//ds:SignatureValue"))));

        X509Certificate tsa = UaPki.FindTimeStampSigner(token, []) ?? throw new InvalidDataException("The TSA certificate is not in the token");
        Assert.True(UaPki.VerifyCmsSigner(Assert.Single(token.GetSignerInfos().GetSigners()), tsa));
    }

    /// <summary>XAdES-B-LT: the OCSP values are signed by their responders and say "good" for the signer and its CA.</summary>
    [Fact]
    public void RevocationValuesAreSignedAndGood()
    {
        XadesFile x = Create(Oids.Dstu7564_256, asicE: false);
        X509Certificate signer = x.SignerCertificate;
        List<X509Certificate> known = [signer, .. x.CertificateValues];

        var covered = new List<X509Certificate>();
        foreach (XmlElement value in x.All("//xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue"))
        {
            BasicOcspResponse response = UaPki.ReadOcspResponse(Convert.FromBase64String(value.InnerText));
            Assert.True(UaPki.VerifyOcsp(response, UaPki.FindOcspResponder(response, known)));
            SingleResponse single = SingleResponse.GetInstance(Assert.Single(response.TbsResponseData.Responses));
            Assert.Equal(0, single.CertStatus.TagNo); // good
            covered.Add(Assert.Single(known, c => c.SerialNumber.Equals(single.CertId.SerialNumber.Value)));
        }
        Assert.Contains(signer, covered);
        Assert.Contains(covered, c => c.SubjectDN.Equivalent(signer.IssuerDN));
    }
}
