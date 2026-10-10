using System.IO.Compression;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>XAdES levels met in the national PKI.</summary>
public enum XadesLevel
{
    /// <summary>XAdES-B-B: signed properties only.</summary>
    B,

    /// <summary>XAdES-B-T: + SignatureTimeStamp over the canonical ds:SignatureValue.</summary>
    T,

    /// <summary>XAdES-B-LT: + CertificateValues and RevocationValues (OCSP).</summary>
    LT,
}

/// <summary>
/// Builds detached XAdES signatures with the <see cref="Hierarchy"/> signer and wraps them into ASiC-E, in the shape
/// produced by Ukrainian qualified signature tools (docs/signature-formats.md, sections 7 and 8). .NET's XML DSig types
/// are used only for exclusive canonicalization; the digests and the signature are this library's.
/// </summary>
internal static class XadesBuilder
{
    public const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    public const string Xades = "http://uri.etsi.org/01903/v1.3.2#";
    public const string Asic = "http://uri.etsi.org/02918/v1.2.1#";
    public const string Manifest = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    public const string AsicEMimeType = "application/vnd.etsi.asic-e+zip";
    public const string ExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    public static string SignatureMethod(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256",
        Oids.Gost34311 => "http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311",
        _ => throw new NotSupportedException(hashOid),
    };

    public static string DigestMethod(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => "http://www.w3.org/2001/04/xmlenc#dstu7564-256",
        Oids.Gost34311 => "http://www.w3.org/2001/04/xmlenc#gost34311",
        _ => throw new NotSupportedException(hashOid),
    };

    /// <summary>The hash OID behind a SignatureMethod or DigestMethod URI.</summary>
    public static string HashOf(string algorithmUri) => algorithmUri switch
    {
        _ when algorithmUri.EndsWith("dstu7564-256", StringComparison.Ordinal) => Oids.Dstu7564_256,
        _ when algorithmUri.EndsWith("gost34311", StringComparison.Ordinal) => Oids.Gost34311,
        _ => throw new NotSupportedException(algorithmUri),
    };

    /// <summary>
    /// A detached XAdES signature over <paramref name="data"/>, referenced by <paramref name="dataUri"/>, with the signer
    /// certificate in ds:KeyInfo and, from level T on, the unsigned properties a long-term validator needs.
    /// </summary>
    public static XmlDocument Build(byte[] data, string dataUri, Hierarchy pki, string hashOid, XadesLevel level = XadesLevel.LT)
    {
        byte[] Hash(byte[] d) => UaPki.Hash(hashOid, d);
        string digestMethod = DigestMethod(hashOid);
        const string signatureId = "signature-1";
        const string dataReferenceId = "reference-data-1";
        const string signedPropertiesId = "signed-properties-1";

        var doc = new XmlDocument { PreserveWhitespace = true };
        XmlElement signature = doc.CreateElement("ds", "Signature", Ds);
        signature.SetAttribute("Id", signatureId);
        doc.AppendChild(signature);

        // SignedInfo: the digests are filled in once the referenced elements exist, the signature last.
        XmlElement signedInfo = Child(signature, "ds", "SignedInfo", Ds);
        Method(signedInfo, "CanonicalizationMethod", ExcC14n);
        Method(signedInfo, "SignatureMethod", SignatureMethod(hashOid));

        XmlElement dataReference = Child(signedInfo, "ds", "Reference", Ds);
        dataReference.SetAttribute("Id", dataReferenceId);
        dataReference.SetAttribute("URI", dataUri);
        Method(dataReference, "DigestMethod", digestMethod);
        Child(dataReference, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(data));

        XmlElement propertiesReference = Child(signedInfo, "ds", "Reference", Ds);
        propertiesReference.SetAttribute("Type", SignedPropertiesType);
        propertiesReference.SetAttribute("URI", "#" + signedPropertiesId);
        Method(Child(propertiesReference, "ds", "Transforms", Ds), "Transform", ExcC14n);
        Method(propertiesReference, "DigestMethod", digestMethod);
        XmlElement propertiesDigest = Child(propertiesReference, "ds", "DigestValue", Ds);

        XmlElement signatureValue = Child(signature, "ds", "SignatureValue", Ds);
        signatureValue.SetAttribute("Id", "signature-value-1");

        XmlElement x509Data = Child(Child(signature, "ds", "KeyInfo", Ds), "ds", "X509Data", Ds);
        Child(x509Data, "ds", "X509Certificate", Ds).InnerText = Convert.ToBase64String(pki.Signer.Certificate.GetEncoded());

        // QualifyingProperties / SignedProperties: signing time, the signer's certificate, the data format.
        XmlElement qualifying = Child(Child(signature, "ds", "Object", Ds), "xades", "QualifyingProperties", Xades);
        qualifying.SetAttribute("Target", "#" + signatureId);
        XmlElement signedProperties = Child(qualifying, "xades", "SignedProperties", Xades);
        signedProperties.SetAttribute("Id", signedPropertiesId);

        XmlElement signatureProperties = Child(signedProperties, "xades", "SignedSignatureProperties", Xades);
        Child(signatureProperties, "xades", "SigningTime", Xades).InnerText = XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc);
        XmlElement certDigest = Child(Child(Child(signatureProperties, "xades", "SigningCertificateV2", Xades), "xades", "Cert", Xades),
            "xades", "CertDigest", Xades);
        Method(certDigest, "DigestMethod", digestMethod);
        Child(certDigest, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(pki.Signer.Certificate.GetEncoded()));

        XmlElement format = Child(Child(signedProperties, "xades", "SignedDataObjectProperties", Xades), "xades", "DataObjectFormat", Xades);
        format.SetAttribute("ObjectReference", "#" + dataReferenceId);
        Child(format, "xades", "MimeType", Xades).InnerText = "application/octet-stream";

        // Sign: the SignedProperties digest, then the canonical SignedInfo.
        propertiesDigest.InnerText = Convert.ToBase64String(Hash(Canonicalize(signedProperties)));
        signatureValue.InnerText = Convert.ToBase64String(TestPki.SignHash(pki.Signer.Key, Hash(Canonicalize(signedInfo))));

        if (level >= XadesLevel.T)
            AddUnsignedProperties(qualifying, signatureValue, pki, hashOid, level);
        return doc;
    }

    private static void AddUnsignedProperties(XmlElement qualifying, XmlElement signatureValue, Hierarchy pki, string hashOid, XadesLevel level)
    {
        XmlElement properties = Child(Child(qualifying, "xades", "UnsignedProperties", Xades), "xades", "UnsignedSignatureProperties", Xades);

        XmlElement timeStamp = Child(properties, "xades", "SignatureTimeStamp", Xades);
        Method(timeStamp, "CanonicalizationMethod", ExcC14n);
        byte[] token = pki.Tsa.Stamp(Canonicalize(signatureValue), hashOid);
        Child(timeStamp, "xades", "EncapsulatedTimeStamp", Xades).InnerText = Convert.ToBase64String(token);

        if (level < XadesLevel.LT)
            return;
        XmlElement certificates = Child(properties, "xades", "CertificateValues", Xades);
        foreach (X509Certificate certificate in pki.ValidationCertificates)
            Child(certificates, "xades", "EncapsulatedX509Certificate", Xades).InnerText = Convert.ToBase64String(certificate.GetEncoded());
        XmlElement ocsp = Child(Child(properties, "xades", "RevocationValues", Xades), "xades", "OCSPValues", Xades);
        foreach (var response in pki.SignerRevocationData)
            Child(ocsp, "xades", "EncapsulatedOCSPValue", Xades).InnerText = Convert.ToBase64String(OcspResponder.Encode(response));
    }

    /// <summary>
    /// An ASiC-E container: mimetype, the data file, META-INF/manifest.xml and META-INF/signatures001.xml with the
    /// signature inside an asic:XAdESSignatures root. Exclusive canonicalization ignores the new root, so the
    /// signature stays valid.
    /// </summary>
    public static byte[] WrapAsicE(string dataName, byte[] data, XmlDocument signature)
    {
        var container = new XmlDocument { PreserveWhitespace = true };
        XmlElement root = container.CreateElement("asic", "XAdESSignatures", Asic);
        root.SetAttribute("xmlns:ds", Ds);
        container.AppendChild(container.CreateXmlDeclaration("1.0", "UTF-8", null));
        container.AppendChild(root);
        root.AppendChild(container.ImportNode(signature.DocumentElement!, deep: true));

        string manifest =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            $"<manifest:manifest xmlns:manifest=\"{Manifest}\">" +
            $"<manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"{AsicEMimeType}\"/>" +
            $"<manifest:file-entry manifest:full-path=\"{dataName}\" manifest:media-type=\"application/octet-stream\"/>" +
            "</manifest:manifest>";

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Zip.WriteMimeType(zip, AsicEMimeType);
            Zip.Write(zip, dataName, data);
            Zip.Write(zip, "META-INF/manifest.xml", Encoding.UTF8.GetBytes(manifest));
            Zip.Write(zip, "META-INF/signatures001.xml", Encoding.UTF8.GetBytes(container.OuterXml));
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Exclusive XML canonicalization (xml-exc-c14n) of an element. The element is re-parsed from its OuterXml, which
    /// carries the namespace declarations it needs; declarations it does not use are dropped by exc-c14n.
    /// </summary>
    public static byte[] Canonicalize(XmlElement element)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(element.OuterXml);
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(doc);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static XmlElement Child(XmlElement parent, string prefix, string name, string ns)
    {
        XmlElement e = parent.OwnerDocument.CreateElement(prefix, name, ns);
        parent.AppendChild(e);
        return e;
    }

    private static void Method(XmlElement parent, string name, string algorithm) =>
        Child(parent, "ds", name, Ds).SetAttribute("Algorithm", algorithm);
}
