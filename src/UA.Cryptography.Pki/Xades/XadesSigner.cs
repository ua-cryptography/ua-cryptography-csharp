using System.Security.Cryptography;
using System.Xml;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Xml;

namespace UA.Cryptography.Pki.Xades;

/// <summary>A file covered by a detached XAdES signature: the name its reference uses and its content.</summary>
public sealed record SignedFile(string Name, byte[] Content);

/// <summary>
/// Creates detached XAdES signatures (ETSI EN 319 132) in the shape of Ukrainian qualified signature tools
/// (docs/signature-formats.md, section 7): one ds:Reference per file, a reference to the signed properties, exclusive
/// canonicalization, the signer's certificate in ds:KeyInfo, and for higher levels a signature time-stamp,
/// certificate values and OCSP values.
/// </summary>
public sealed class XadesSigner(SigningKey signer, SignatureServices? services = null)
{
    public const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    public const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";
    public const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    private readonly SignatureServices _services = services ?? new SignatureServices();

    /// <summary>A ds:Signature document over <paramref name="files"/>.</summary>
    public XmlDocument Sign(IReadOnlyList<SignedFile> files, string hashOid = Oids.Dstu7564_256, SignatureLevel level = SignatureLevel.B)
    {
        if (files.Count == 0)
            throw new ArgumentException("Nothing to sign.", nameof(files));
        byte[] Hash(byte[] d) => PkiAlgorithms.Hash(hashOid, d, signer.Key.Dke);
        string digestMethod = PkiAlgorithms.XmlDigestMethod(hashOid);
        string id = "S-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

        var doc = new XmlDocument { PreserveWhitespace = true };
        XmlElement signature = doc.CreateElement("ds", "Signature", Ds);
        signature.SetAttribute("Id", id);
        doc.AppendChild(signature);

        XmlElement signedInfo = Child(signature, "ds", "SignedInfo", Ds);
        Method(signedInfo, "CanonicalizationMethod", XmlCanonicalizer.ExclusiveC14N);
        Method(signedInfo, "SignatureMethod", PkiAlgorithms.XmlSignatureMethod(hashOid));
        for (int i = 0; i < files.Count; i++)
        {
            XmlElement reference = Child(signedInfo, "ds", "Reference", Ds);
            reference.SetAttribute("Id", $"{id}-Reference-{i + 1}");
            reference.SetAttribute("URI", Uri.EscapeDataString(files[i].Name).Replace("%2F", "/", StringComparison.Ordinal));
            Method(reference, "DigestMethod", digestMethod);
            Child(reference, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(files[i].Content));
        }
        XmlElement propertiesReference = Child(signedInfo, "ds", "Reference", Ds);
        propertiesReference.SetAttribute("Type", SignedPropertiesType);
        propertiesReference.SetAttribute("URI", $"#{id}-SignedProperties");
        Method(Child(propertiesReference, "ds", "Transforms", Ds), "Transform", XmlCanonicalizer.ExclusiveC14N);
        Method(propertiesReference, "DigestMethod", digestMethod);
        XmlElement propertiesDigest = Child(propertiesReference, "ds", "DigestValue", Ds);

        XmlElement signatureValue = Child(signature, "ds", "SignatureValue", Ds);
        signatureValue.SetAttribute("Id", $"{id}-SignatureValue");
        XmlElement x509Data = Child(Child(signature, "ds", "KeyInfo", Ds), "ds", "X509Data", Ds);
        Child(x509Data, "ds", "X509Certificate", Ds).InnerText = Convert.ToBase64String(signer.Certificate.Encoded);

        XmlElement qualifying = Child(Child(signature, "ds", "Object", Ds), "xades", "QualifyingProperties", XadesNamespace);
        qualifying.SetAttribute("Target", "#" + id);
        XmlElement signedProperties = Child(qualifying, "xades", "SignedProperties", XadesNamespace);
        signedProperties.SetAttribute("Id", $"{id}-SignedProperties");
        XmlElement signatureProperties = Child(signedProperties, "xades", "SignedSignatureProperties", XadesNamespace);
        // Whole seconds, as "Дія" and IIT write it.
        DateTime now = DateTime.UtcNow;
        Child(signatureProperties, "xades", "SigningTime", XadesNamespace).InnerText =
            XmlConvert.ToString(now.AddTicks(-(now.Ticks % TimeSpan.TicksPerSecond)), XmlDateTimeSerializationMode.Utc);
        XmlElement certDigest = Child(Child(Child(signatureProperties, "xades", "SigningCertificateV2", XadesNamespace), "xades", "Cert", XadesNamespace),
            "xades", "CertDigest", XadesNamespace);
        Method(certDigest, "DigestMethod", digestMethod);
        Child(certDigest, "ds", "DigestValue", Ds).InnerText = Convert.ToBase64String(Hash(signer.Certificate.Encoded));

        XmlElement dataProperties = Child(signedProperties, "xades", "SignedDataObjectProperties", XadesNamespace);
        for (int i = 0; i < files.Count; i++)
        {
            XmlElement format = Child(dataProperties, "xades", "DataObjectFormat", XadesNamespace);
            format.SetAttribute("ObjectReference", $"#{id}-Reference-{i + 1}");
            Child(format, "xades", "MimeType", XadesNamespace).InnerText = MimeTypes.Of(files[i].Name);
        }

        propertiesDigest.InnerText = Convert.ToBase64String(Hash(XmlCanonicalizer.Canonicalize(signedProperties, XmlCanonicalizer.ExclusiveC14N)));
        byte[] signedInfoHash = Hash(XmlCanonicalizer.Canonicalize(signedInfo, XmlCanonicalizer.ExclusiveC14N));
        signatureValue.InnerText = Convert.ToBase64String(signer.Key.SignHash(signedInfoHash));

        if (level >= SignatureLevel.T)
            AddUnsignedProperties(qualifying, signatureValue, hashOid, level);
        return doc;
    }

    /// <summary>The signature as bytes (UTF-8 XML).</summary>
    public byte[] SignToBytes(IReadOnlyList<SignedFile> files, string hashOid = Oids.Dstu7564_256, SignatureLevel level = SignatureLevel.B) =>
        XmlSafe.Save(Sign(files, hashOid, level));

    private void AddUnsignedProperties(XmlElement qualifying, XmlElement signatureValue, string hashOid, SignatureLevel level)
    {
        XmlElement properties = Child(Child(qualifying, "xades", "UnsignedProperties", XadesNamespace),
            "xades", "UnsignedSignatureProperties", XadesNamespace);
        XmlElement timeStamp = Child(properties, "xades", "SignatureTimeStamp", XadesNamespace);
        Method(timeStamp, "CanonicalizationMethod", XmlCanonicalizer.ExclusiveC14N);
        byte[] covered = XmlCanonicalizer.Canonicalize(signatureValue, XmlCanonicalizer.ExclusiveC14N);
        var token = _services.RequireTimeStamps().GetToken(PkiAlgorithms.Hash(hashOid, covered), hashOid);
        Child(timeStamp, "xades", "EncapsulatedTimeStamp", XadesNamespace).InnerText = Convert.ToBase64String(token.Encoded);
        if (level < SignatureLevel.LT)
            return;

        LongTermValidationData data = _services.CollectLongTermData(signer, hashOid);
        var certificates = data.Certificates.ToList();
        foreach (var c in token.Cms.Certificates)
        {
            if (!certificates.Contains(c) && !c.Equals(signer.Certificate))
                certificates.Add(c);
        }
        XmlElement values = Child(properties, "xades", "CertificateValues", XadesNamespace);
        foreach (var certificate in certificates)
            Child(values, "xades", "EncapsulatedX509Certificate", XadesNamespace).InnerText = Convert.ToBase64String(certificate.Encoded);
        XmlElement ocsp = Child(Child(properties, "xades", "RevocationValues", XadesNamespace), "xades", "OCSPValues", XadesNamespace);
        foreach (var response in data.Responses)
            Child(ocsp, "xades", "EncapsulatedOCSPValue", XadesNamespace).InnerText = Convert.ToBase64String(response.FullEncoded);
    }

    internal static XmlElement Child(XmlElement parent, string prefix, string name, string ns)
    {
        XmlElement e = parent.OwnerDocument.CreateElement(prefix, name, ns);
        parent.AppendChild(e);
        return e;
    }

    private static void Method(XmlElement parent, string name, string algorithm) =>
        Child(parent, "ds", name, Ds).SetAttribute("Algorithm", algorithm);
}

/// <summary>Media types of signed files, by extension.</summary>
public static class MimeTypes
{
    public static string Of(string fileName) => Path.GetExtension(fileName).ToLowerInvariant() switch
    {
        ".pdf" => "application/pdf",
        ".xml" => "application/xml",
        ".txt" => "text/plain",
        ".json" => "application/json",
        ".doc" => "application/msword",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls" => "application/vnd.ms-excel",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".zip" => "application/zip",
        _ => "application/octet-stream",
    };
}
