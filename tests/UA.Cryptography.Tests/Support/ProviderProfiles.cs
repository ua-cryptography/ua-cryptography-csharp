using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using AttributeCms = Org.BouncyCastle.Asn1.Cms.Attribute;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// The PrivatBank signature profile (docs/provider-formats.md, section 1): an enveloped CAdES-T, DSTU 4145 with
/// DSTU 7564-256, handed out as <c>.sig</c>. <see cref="Build"/> makes a signature the way the bank does — including
/// what the bank leaves out — and <see cref="AssertProfile"/> checks that a signature has the profile, independently of
/// the package (BouncyCastle CMS).
/// </summary>
internal static class PrivatBankSig
{
    /// <summary>
    /// As the bank hands it out: signed attributes contentType, signingTime, messageDigest and signingCertificateV2 with
    /// issuerSerial; the signature time-stamp without the TSA's certificate; only the signer's certificate inside.
    /// </summary>
    public static byte[] Build(byte[] data, Hierarchy pki, TestPki.TestIdentity signer)
    {
        var signingTime = new AttributeCms(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new Org.BouncyCastle.Asn1.X509.Time(DateTime.UtcNow)));
        SignerInfo info = CmsBuilder.CreateSignerInfo(data, CmsObjectIdentifiers.Data, signer, Oids.Dstu7564_256, [signingTime], issuerSerial: true);
        byte[] token = pki.Tsa.Stamp(info.Signature.GetOctets(), Oids.Dstu7564_256, includeCertificate: false);
        info = CmsBuilder.WithUnsignedAttributes(info,
            [new AttributeCms(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, new DerSet(Asn1Object.FromByteArray(token)))]);
        return CmsBuilder.SignedData(info, CmsObjectIdentifiers.Data, data, [signer.Certificate]).GetDerEncoded();
    }

    /// <summary>The profile, whoever made the signature. The time-stamp token may or may not carry the TSA's certificate.</summary>
    public static void AssertProfile(byte[] signature, byte[] data, X509Certificate signer)
    {
        var cms = new CmsSignedData(signature);
        Assert.Equal(CmsObjectIdentifiers.Data.Id, cms.SignedContentType.Id);
        Assert.Equal(data, ((Asn1OctetString)SignedData.GetInstance(cms.ContentInfo.Content).EncapContentInfo.Content).GetOctets());
        Assert.Equal(signer, Assert.Single(cms.GetCertificates().EnumerateMatches(null)));

        SignerInformation info = Assert.Single(cms.GetSignerInfos().GetSigners());
        Assert.Equal(1, info.Version);
        Assert.Equal(signer.SerialNumber, info.SignerID.SerialNumber);
        Assert.True(signer.IssuerDN.Equivalent(info.SignerID.Issuer));
        Assert.Equal(Oids.Dstu7564_256, info.DigestAlgorithmID.Algorithm.Id);
        Assert.Equal(Oids.Dstu4145WithDstu7564, info.SignatureAlgorithm.Algorithm.Id);
        Assert.True(UaPki.VerifyCmsSigner(info, signer));

        string[] signed = AttributeOids(info.SignedAttributes);
        Assert.Equal(new[] { PkcsObjectIdentifiers.Pkcs9AtContentType, PkcsObjectIdentifiers.Pkcs9AtSigningTime,
            PkcsObjectIdentifiers.Pkcs9AtMessageDigest, PkcsObjectIdentifiers.IdAASigningCertificateV2 }.Select(o => o.Id).Order(), signed.Order());
        Assert.IsAssignableFrom<Asn1UtcTime>(UaPki.SignedAttribute(info, PkcsObjectIdentifiers.Pkcs9AtSigningTime));
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, data), UaPki.MessageDigest(info));

        EssCertIDv2 id = Assert.Single(SigningCertificateV2.GetInstance(UaPki.SignedAttribute(info, PkcsObjectIdentifiers.IdAASigningCertificateV2)).GetCerts());
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, signer.GetEncoded()), id.GetCertHash());
        Assert.NotNull(id.IssuerSerial);
        Assert.Equal(signer.SerialNumber, id.IssuerSerial.Serial.Value);
        Assert.Equal(signer.IssuerDN.GetEncoded(), Assert.Single(id.IssuerSerial.Issuer.GetNames()).Name.ToAsn1Object().GetEncoded());

        Assert.Equal([PkcsObjectIdentifiers.IdAASignatureTimeStampToken.Id], AttributeOids(info.UnsignedAttributes));
        var token = new CmsSignedData(UaPki.UnsignedAttribute(info, PkcsObjectIdentifiers.IdAASignatureTimeStampToken).GetEncoded());
        var tst = UaPki.ReadTimeStamp(token);
        Assert.Equal(Oids.TspPolicyDstu7564, tst.Policy.Id);
        Assert.Equal(Oids.Dstu7564_256, tst.MessageImprint.HashAlgorithm.Algorithm.Id);
        Assert.True(UaPki.ImprintCovers(tst, info.GetSignature()));
    }

    private static string[] AttributeOids(Org.BouncyCastle.Asn1.Cms.AttributeTable table) =>
        table.ToAsn1EncodableVector().Cast<AttributeCms>().Select(a => a.AttrType.Id).ToArray();
}

/// <summary>
/// The "Дія" signature profile (docs/provider-formats.md, section 2): ASiC-E with a detached XAdES-B-LT, DSTU 4145 with
/// DSTU 7564-256. <see cref="Build"/> makes a container the way "Дія" does, down to its identifiers, namespace
/// declarations and the zero issuerKeyHash in its OCSP response; <see cref="AssertProfile"/> checks that a container
/// has the profile, independently of the package (System.IO.Compression, System.Xml, BouncyCastle).
/// </summary>
internal static class DiiaAsicE
{
    private const string Ds = XadesBuilder.Ds;
    private const string Xades = XadesBuilder.Xades;
    private const string Xsi = "http://www.w3.org/2001/XMLSchema-instance";
    private const string SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256";
    private const string DigestMethod = "http://www.w3.org/2001/04/xmlenc#dstu7564-256";
    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    /// <summary>
    /// As "Дія" makes it: ids <c>id-…</c>, <c>xades-id-…</c>, <c>TS-…</c>, an empty Type on the data reference,
    /// application/octet-stream, the signing time in whole seconds; the signature time-stamp with the TSA's certificate;
    /// CertificateValues with the CA, the root and the OCSP responder; one OCSP response, about the signer, whose CertID
    /// has a zero issuerKeyHash.
    /// </summary>
    public static byte[] Build(byte[] data, string name, Hierarchy pki)
    {
        byte[] Hash(byte[] d) => UaPki.Hash(Oids.Dstu7564_256, d);
        string id = "id-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        string stampId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var doc = new XmlDocument { PreserveWhitespace = true };
        XmlElement signature = Child(doc, "ds", "Signature", Ds);
        signature.SetAttribute("Id", id);
        XmlElement signedInfo = Child(signature, "ds", "SignedInfo", Ds);
        Method(signedInfo, "CanonicalizationMethod", XadesBuilder.ExcC14n);
        Method(signedInfo, "SignatureMethod", SignatureMethod);
        XmlElement dataReference = Child(signedInfo, "ds", "Reference", Ds);
        dataReference.SetAttribute("Id", id + "-1");
        dataReference.SetAttribute("Type", "");
        dataReference.SetAttribute("URI", name);
        Method(dataReference, "DigestMethod", DigestMethod);
        Child(dataReference, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(data));
        XmlElement propertiesReference = Child(signedInfo, "ds", "Reference", Ds);
        propertiesReference.SetAttribute("Type", SignedPropertiesType);
        propertiesReference.SetAttribute("URI", "#xades-" + id);
        Method(Child(propertiesReference, "ds", "Transforms", Ds), "Transform", XadesBuilder.ExcC14n);
        Method(propertiesReference, "DigestMethod", DigestMethod);
        XmlElement propertiesDigest = Child(propertiesReference, "ds", "DigestValue", Ds);

        XmlElement signatureValue = Child(signature, "ds", "SignatureValue", Ds);
        Child(Child(Child(signature, "ds", "KeyInfo", Ds), "ds", "X509Data", Ds), "ds", "X509Certificate", Ds).InnerText =
            Convert.ToBase64String(pki.Signer.Certificate.GetEncoded());

        XmlElement qualifying = Child(Child(signature, "ds", "Object", Ds), "xades", "QualifyingProperties", Xades);
        qualifying.SetAttribute("Target", "#" + id);
        XmlElement signedProperties = Child(qualifying, "xades", "SignedProperties", Xades);
        signedProperties.SetAttribute("Id", "xades-" + id);
        XmlElement signatureProperties = Child(signedProperties, "xades", "SignedSignatureProperties", Xades);
        Child(signatureProperties, "xades", "SigningTime", Xades).InnerText = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        XmlElement certDigest = Child(Child(Child(signatureProperties, "xades", "SigningCertificateV2", Xades), "xades", "Cert", Xades),
            "xades", "CertDigest", Xades);
        Method(certDigest, "DigestMethod", DigestMethod);
        Child(certDigest, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(pki.Signer.Certificate.GetEncoded()));
        XmlElement format = Child(Child(signedProperties, "xades", "SignedDataObjectProperties", Xades), "xades", "DataObjectFormat", Xades);
        format.SetAttribute("ObjectReference", $"#{id}-1");
        Child(format, "xades", "MimeType", Xades).InnerText = "application/octet-stream";

        propertiesDigest.InnerText = Convert.ToBase64String(Hash(XadesBuilder.Canonicalize(signedProperties)));
        signatureValue.InnerText = Convert.ToBase64String(TestPki.SignHash(pki.Signer.Key, Hash(XadesBuilder.Canonicalize(signedInfo))));

        XmlElement unsigned = Child(Child(qualifying, "xades", "UnsignedProperties", Xades), "xades", "UnsignedSignatureProperties", Xades);
        XmlElement stamp = Child(unsigned, "xades", "SignatureTimeStamp", Xades);
        stamp.SetAttribute("Id", "TS-" + stampId);
        Method(stamp, "CanonicalizationMethod", XadesBuilder.ExcC14n);
        XmlElement encapsulated = Child(stamp, "xades", "EncapsulatedTimeStamp", Xades);
        encapsulated.SetAttribute("Id", "ETS-" + stampId);
        encapsulated.InnerText = Convert.ToBase64String(pki.Tsa.Stamp(XadesBuilder.Canonicalize(signatureValue), Oids.Dstu7564_256));
        XmlElement values = Child(unsigned, "xades", "CertificateValues", Xades);
        foreach (X509Certificate c in new[] { pki.IssuingCa.Certificate, pki.Root.Certificate, pki.IssuingCaOcsp.Identity.Certificate })
            Child(values, "xades", "EncapsulatedX509Certificate", Xades).InnerText = Convert.ToBase64String(c.GetEncoded());
        Child(Child(Child(unsigned, "xades", "RevocationValues", Xades), "xades", "OCSPValues", Xades), "xades", "EncapsulatedOCSPValue", Xades)
            .InnerText = Convert.ToBase64String(OcspResponder.Encode(
                pki.IssuingCaOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate, zeroKeyHash: true)));

        // The container: the root declares the namespaces, as "Дія" writes it; exclusive canonicalization ignores them.
        var container = new XmlDocument { PreserveWhitespace = true };
        container.AppendChild(container.CreateXmlDeclaration("1.0", "utf-8", "no"));
        XmlElement root = Child(container, "asic", "XAdESSignatures", XadesBuilder.Asic);
        root.SetAttribute("xmlns:ds", Ds);
        root.SetAttribute("xmlns:xades", Xades);
        root.SetAttribute("xmlns:xsi", Xsi);
        root.AppendChild(container.ImportNode(signature, deep: true));

        string manifest =
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>" +
            $"<manifest:manifest xmlns:manifest=\"{XadesBuilder.Manifest}\">" +
            $"<manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"{XadesBuilder.AsicEMimeType}\"/>" +
            $"<manifest:file-entry manifest:full-path=\"{name}\" manifest:media-type=\"application/octet-stream\"/>" +
            "</manifest:manifest>";
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Zip.WriteMimeType(zip, XadesBuilder.AsicEMimeType);
            Zip.Write(zip, name, data);
            Zip.Write(zip, "META-INF/manifest.xml", Encoding.UTF8.GetBytes(manifest));
            Zip.Write(zip, "META-INF/signatures001.xml", Encoding.UTF8.GetBytes(container.OuterXml));
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// The profile, whoever made the container. Identifiers, MIME types and namespace placement may differ; with
    /// <paramref name="ocspFor"/> the RevocationValues must hold a "good" response about that certificate.
    /// </summary>
    public static void AssertProfile(byte[] container, string name, byte[] data, X509Certificate signer, X509Certificate issuer,
        X509Certificate? ocspFor = null)
    {
        using var zip = new ZipArchive(new MemoryStream(container), ZipArchiveMode.Read);
        Assert.Equal(["mimetype", name, "META-INF/manifest.xml", "META-INF/signatures001.xml"], zip.Entries.Select(e => e.FullName));
        ZipArchiveEntry mimetype = zip.Entries[0];
        Assert.Equal(mimetype.Length, mimetype.CompressedLength);
        Assert.Equal(XadesBuilder.AsicEMimeType, Encoding.ASCII.GetString(Zip.Read(mimetype)));
        Assert.Equal(data, Zip.Read(zip.Entries[1]));

        var manifest = new XmlDocument();
        manifest.LoadXml(Encoding.UTF8.GetString(Zip.Read(zip.Entries[2])));
        Assert.Equal(["/", name], manifest.GetElementsByTagName("file-entry", XadesBuilder.Manifest).Cast<XmlElement>()
            .Select(e => e.GetAttribute("full-path", XadesBuilder.Manifest)));

        var xml = new XmlDocument { PreserveWhitespace = true };
        xml.LoadXml(Encoding.UTF8.GetString(Zip.Read(zip.Entries[3])).TrimStart('﻿'));
        var ns = new XmlNamespaceManager(xml.NameTable);
        ns.AddNamespace("asic", XadesBuilder.Asic);
        ns.AddNamespace("ds", Ds);
        ns.AddNamespace("xades", Xades);
        Assert.Equal(("XAdESSignatures", XadesBuilder.Asic), (xml.DocumentElement!.LocalName, xml.DocumentElement.NamespaceURI));
        XmlElement signature = Assert.Single(xml.SelectNodes("/asic:XAdESSignatures/ds:Signature", ns)!.Cast<XmlElement>());
        XmlElement Single(XmlNode parent, string xpath) => Assert.Single(parent.SelectNodes(xpath, ns)!.Cast<XmlElement>());

        // SignedInfo: exclusive C14N, DSTU 4145 + DSTU 7564-256, the file and the signed properties.
        XmlElement signedInfo = Single(signature, "ds:SignedInfo");
        Assert.Equal(XadesBuilder.ExcC14n, Single(signedInfo, "ds:CanonicalizationMethod").GetAttribute("Algorithm"));
        Assert.Equal(SignatureMethod, Single(signedInfo, "ds:SignatureMethod").GetAttribute("Algorithm"));
        XmlElement[] references = signedInfo.SelectNodes("ds:Reference", ns)!.Cast<XmlElement>().ToArray();
        Assert.Equal(2, references.Length);
        Assert.Equal(name, references[0].GetAttribute("URI"));
        Assert.Equal(DigestMethod, Single(references[0], "ds:DigestMethod").GetAttribute("Algorithm"));
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, data), Convert.FromBase64String(Single(references[0], "ds:DigestValue").InnerText));
        Assert.Equal(SignedPropertiesType, references[1].GetAttribute("Type"));
        Assert.Equal(XadesBuilder.ExcC14n, Single(references[1], "ds:Transforms/ds:Transform").GetAttribute("Algorithm"));

        Assert.Equal(signer.GetEncoded(), Convert.FromBase64String(Single(signature, "ds:KeyInfo/ds:X509Data/ds:X509Certificate").InnerText));
        XmlElement qualifying = Single(signature, "ds:Object/xades:QualifyingProperties");
        Assert.Equal("#" + signature.GetAttribute("Id"), qualifying.GetAttribute("Target"));

        // SignedProperties: the one the second reference covers, with its digest; signing time, certificate, data format.
        XmlElement signedProperties = Single(qualifying, "xades:SignedProperties");
        Assert.Equal("#" + signedProperties.GetAttribute("Id"), references[1].GetAttribute("URI"));
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, XadesBuilder.Canonicalize(signedProperties)),
            Convert.FromBase64String(Single(references[1], "ds:DigestValue").InnerText));
        XmlConvert.ToDateTimeOffset(Single(signedProperties, "xades:SignedSignatureProperties/xades:SigningTime").InnerText);
        XmlElement certDigest = Single(signedProperties, "xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert/xades:CertDigest");
        Assert.Equal(DigestMethod, Single(certDigest, "ds:DigestMethod").GetAttribute("Algorithm"));
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, signer.GetEncoded()), Convert.FromBase64String(Single(certDigest, "ds:DigestValue").InnerText));
        XmlElement format = Single(signedProperties, "xades:SignedDataObjectProperties/xades:DataObjectFormat");
        Assert.Equal("#" + references[0].GetAttribute("Id"), format.GetAttribute("ObjectReference"));
        Assert.NotEmpty(Single(format, "xades:MimeType").InnerText);

        // The DSTU 4145 signature over the canonical SignedInfo.
        var (parameters, key, _) = UaPki.ReadPublicKey(signer);
        Assert.True(UaPki.VerifyDstu4145(parameters, key, UaPki.Hash(Oids.Dstu7564_256, XadesBuilder.Canonicalize(signedInfo)),
            Convert.FromBase64String(Single(signature, "ds:SignatureValue").InnerText)));

        // Level LT: the time-stamp over the canonical SignatureValue, the CA certificate, OCSP responses.
        XmlElement unsigned = Single(qualifying, "xades:UnsignedProperties/xades:UnsignedSignatureProperties");
        XmlElement stamp = Single(unsigned, "xades:SignatureTimeStamp");
        Assert.Equal(XadesBuilder.ExcC14n, Single(stamp, "ds:CanonicalizationMethod").GetAttribute("Algorithm"));
        var tst = UaPki.ReadTimeStamp(new CmsSignedData(Convert.FromBase64String(Single(stamp, "xades:EncapsulatedTimeStamp").InnerText)));
        Assert.Equal(Oids.TspPolicyDstu7564, tst.Policy.Id);
        Assert.True(UaPki.ImprintCovers(tst, XadesBuilder.Canonicalize(Single(signature, "ds:SignatureValue"))));
        Assert.Contains(unsigned.SelectNodes("xades:CertificateValues/xades:EncapsulatedX509Certificate", ns)!.Cast<XmlElement>(),
            e => Convert.FromBase64String(e.InnerText).SequenceEqual(issuer.GetEncoded()));
        BasicOcspResponse[] responses = unsigned.SelectNodes("xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue", ns)!
            .Cast<XmlElement>().Select(e => UaPki.ReadOcspResponse(Convert.FromBase64String(e.InnerText))).ToArray();
        Assert.NotEmpty(responses);
        if (ocspFor is not null)
        {
            SingleResponse about = responses.SelectMany(r => r.TbsResponseData.Responses.Cast<Asn1Encodable>().Select(SingleResponse.GetInstance))
                .Single(s => s.CertId.SerialNumber.Value.Equals(ocspFor.SerialNumber));
            Assert.Equal(0, about.CertStatus.TagNo);
        }
    }

    private static XmlElement Child(XmlNode parent, string prefix, string name, string ns)
    {
        XmlDocument document = parent as XmlDocument ?? parent.OwnerDocument!;
        XmlElement e = document.CreateElement(prefix, name, ns);
        parent.AppendChild(e);
        return e;
    }

    private static void Method(XmlElement parent, string name, string algorithm) =>
        Child(parent, "ds", name, Ds).SetAttribute("Algorithm", algorithm);
}
