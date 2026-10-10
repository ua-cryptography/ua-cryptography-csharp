using System.Xml;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using UA.Cryptography.Pki.Xml;

namespace UA.Cryptography.Pki.Xades;

/// <summary>
/// Verifies XAdES signatures (docs/signature-formats.md, section 7): every ds:Reference, the signed properties and the
/// signing certificate they name, the DSTU 4145 signature over the canonical ds:SignedInfo, the signature time-stamp,
/// the certificate and OCSP values, and the certificate path.
/// </summary>
/// <remarks>
/// Against signature wrapping, same-document references must resolve to exactly one element, and the signed
/// properties are read only from the element the signature actually covers, inside this ds:Signature.
/// </remarks>
public static class XadesVerifier
{
    private const string Ds = XadesSigner.Ds;
    private const string Xades = XadesSigner.XadesNamespace;
    private const string Xades141 = "http://uri.etsi.org/01903/v1.4.1#";
    private const string EnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /// <summary>
    /// Verifies every ds:Signature of <paramref name="document"/>. <paramref name="resolve"/> returns the content of an
    /// external reference (a file name, already URI-unescaped) or null when it is not available.
    /// </summary>
    public static List<VerificationReport> Verify(XmlDocument document, Func<string, byte[]?> resolve, ValidationOptions options)
    {
        var ns = Namespaces(document);
        List<XmlElement> signatures = document.SelectNodes("//ds:Signature", ns)!.Cast<XmlElement>().ToList();
        var reports = new List<VerificationReport>();
        foreach (XmlElement signature in signatures)
        {
            string id = signature.GetAttribute("Id");
            var report = new VerificationReport(id.Length > 0 ? $"XAdES signature {id}" : "XAdES signature");
            try
            {
                VerifySignature(document, signature, ns, resolve, options, report);
            }
            catch (Exception e) when (e is InvalidDataException or FormatException or NotSupportedException or XmlException)
            {
                report.Fail("structure", e.Message);
            }
            reports.Add(report);
        }
        return reports;
    }

    /// <summary>The names of the external files the signatures of <paramref name="document"/> reference.</summary>
    public static IReadOnlyList<string> ExternalReferences(XmlDocument document) =>
        document.SelectNodes("//ds:Signature/ds:SignedInfo/ds:Reference", Namespaces(document))!.Cast<XmlElement>()
            .Select(r => r.GetAttribute("URI"))
            .Where(u => u.Length > 0 && !u.StartsWith('#'))
            .Select(Uri.UnescapeDataString)
            .ToList();

    private static XmlNamespaceManager Namespaces(XmlDocument document)
    {
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("ds", Ds);
        ns.AddNamespace("xades", Xades);
        ns.AddNamespace("xades141", Xades141);
        return ns;
    }

    private static void VerifySignature(XmlDocument document, XmlElement signature, XmlNamespaceManager ns, Func<string, byte[]?> resolve,
        ValidationOptions options, VerificationReport report)
    {
        XmlElement signedInfo = Single(signature, "ds:SignedInfo", ns);
        string canonicalization = Single(signedInfo, "ds:CanonicalizationMethod", ns).GetAttribute("Algorithm");
        string signatureMethod = Single(signedInfo, "ds:SignatureMethod", ns).GetAttribute("Algorithm");
        string signatureHash = PkiAlgorithms.HashOfXmlAlgorithm(signatureMethod);

        // The signed properties: the element of type SignedProperties inside this signature that a reference covers.
        XmlElement? qualifying = signature.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) as XmlElement;
        XmlElement? signedProperties = null;
        var externalFiles = new List<string>();

        // References: resolve each one first; the digests are compared once the signer's key (and its DKE) is known.
        var references = new List<(string Name, string Hash, byte[] Expected, byte[]? Content)>();
        foreach (XmlElement reference in signedInfo.SelectNodes("ds:Reference", ns)!.Cast<XmlElement>())
        {
            string uri = reference.GetAttribute("URI");
            string name = $"reference '{(uri.Length == 0 ? "(document)" : uri)}'";
            string digestHash = PkiAlgorithms.HashOfXmlAlgorithm(Single(reference, "ds:DigestMethod", ns).GetAttribute("Algorithm"));
            byte[] expected = Convert.FromBase64String(Single(reference, "ds:DigestValue", ns).InnerText.Trim());
            List<(string Algorithm, IReadOnlyCollection<string>? Prefixes)> transforms = Transforms(reference, ns);

            byte[]? content;
            if (uri.StartsWith('#') || uri.Length == 0)
            {
                XmlNode target = uri.Length == 0 ? document : FindById(document, uri[1..]);
                content = ApplyTransforms(target, transforms, signature);
                if (target is XmlElement element && element.LocalName == "SignedProperties"
                    && (element.NamespaceURI == Xades || element.NamespaceURI == Xades141) && IsDescendant(element, signature))
                    signedProperties = element;
            }
            else
            {
                string file = Uri.UnescapeDataString(uri);
                if (transforms.Count > 0)
                    throw new NotSupportedException($"Transforms on the external reference '{uri}' are not supported.");
                content = resolve(file);
                if (content is not null)
                    externalFiles.Add(file);
            }
            references.Add((name, digestHash, expected, content));
        }

        // The signer's certificate: ds:KeyInfo, else the one the signed properties name.
        List<Certificate> certificateValues = ReadAll(signature, "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/"
            + "xades:UnsignedSignatureProperties/xades:CertificateValues/xades:EncapsulatedX509Certificate", ns)
            .Select(b => Certificate.Load(b)).ToList();
        List<Certificate> keyInfo = ReadAll(signature, "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns).Select(b => Certificate.Load(b)).ToList();
        List<Certificate> known = [.. keyInfo, .. certificateValues, .. options.ExtraCertificates];

        if (signedProperties is null)
        {
            report.Fail("signed properties", qualifying is null
                ? "the signature has no xades:QualifyingProperties (plain XML-DSig)"
                : "no reference of this signature covers its xades:SignedProperties");
        }
        Certificate? certificate = signedProperties is null ? keyInfo.FirstOrDefault() : FindSigningCertificate(signedProperties, known, ns, report);
        if (certificate is null)
        {
            report.Fail("signer certificate", "the signer's certificate is neither in ds:KeyInfo nor given");
            return;
        }
        report.Signer = certificate;
        byte[]? dke = certificate.PublicKey.Dke;
        foreach (var (name, hash, expected, content) in references)
        {
            if (content is null)
            {
                report.Fail(name, "the referenced file was not given");
                continue;
            }
            bool matches = PkiAlgorithms.DigestMatches(hash, content, expected, dke);
            report.Check(name, matches, matches ? $"{PkiAlgorithms.HashName(hash)} digest matches" : "the content does not match the digest");
        }

        if (signedProperties?.SelectSingleNode("xades:SignedSignatureProperties/xades:SigningTime", ns) is XmlElement time)
            report.ClaimedSigningTime = XmlConvert.ToDateTimeOffset(time.InnerText.Trim()).ToUniversalTime();

        // The signature over the canonical SignedInfo.
        XmlElement signatureValue = Single(signature, "ds:SignatureValue", ns);
        byte[] value = Convert.FromBase64String(signatureValue.InnerText.Trim());
        byte[] canonical = XmlCanonicalizer.Canonicalize(signedInfo, canonicalization, InclusivePrefixes(Single(signedInfo, "ds:CanonicalizationMethod", ns), ns));
        bool valid = certificate.PublicKey.VerifyData(signatureHash, canonical, value);
        report.Check("signature", valid, valid
            ? $"DSTU 4145 signature of {CertificatePathValidator.Short(certificate)} over ds:SignedInfo"
            : "the DSTU 4145 signature does not verify");

        // Unsigned properties: the signature time-stamp and the long-term values.
        XmlElement? unsigned = qualifying?.SelectSingleNode("xades:UnsignedProperties/xades:UnsignedSignatureProperties", ns) as XmlElement;
        List<Certificate> pool = [.. known];
        bool hasTimeStamp = false;
        foreach (XmlElement stamp in unsigned?.SelectNodes("xades:SignatureTimeStamp", ns)!.Cast<XmlElement>() ?? [])
        {
            hasTimeStamp = true;
            string method = (stamp.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? XmlCanonicalizer.InclusiveC14N;
            byte[] covered = XmlCanonicalizer.Canonicalize(signatureValue, method);
            TimeStampToken token = TimeStampToken.Load(Convert.FromBase64String(Single(stamp, "xades:EncapsulatedTimeStamp", ns).InnerText.Trim()));
            int before = report.Checks.Count;
            Certificate? tsa = token.Verify(covered, pool, report, "signature time-stamp");
            if (tsa is not null)
            {
                pool.AddRange(token.Cms.Certificates);
                CertificatePathValidator.Validate(tsa, pool, [], options, token.GenTime, report, "signature time-stamp service");
            }
            if (report.Checks.Skip(before).All(c => c.Status != CheckStatus.Failed))
                report.TimeStampTime ??= token.GenTime;
        }

        List<OcspResponse> ocsp = unsigned is null ? [] : ReadAll(unsigned, "xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue", ns)
            .Select(b => OcspResponse.Load(b)).ToList();
        report.Format = $"XAdES-B-{(certificateValues.Count > 0 || ocsp.Count > 0 ? "LT" : hasTimeStamp ? "T" : "B")}, "
            + $"{(externalFiles.Count > 0 ? "detached" : "enveloped")}, {PkiAlgorithms.HashName(signatureHash)}";

        CertificatePathValidator.Validate(certificate, pool, ocsp, options, report.ValidationTime, report, "signer");
    }

    /// <summary>SigningCertificateV2 / SigningCertificate: the certificate whose digest is listed (the first Cert names the signer).</summary>
    private static Certificate? FindSigningCertificate(XmlElement signedProperties, List<Certificate> known, XmlNamespaceManager ns, VerificationReport report)
    {
        XmlElement? cert = signedProperties.SelectSingleNode(
            "xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert | xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", ns) as XmlElement;
        if (cert is null)
        {
            report.Warn("signing certificate", "the signed properties do not name the certificate");
            return known.FirstOrDefault();
        }
        XmlElement digest = Single(cert, "xades:CertDigest", ns);
        string hash = PkiAlgorithms.HashOfXmlAlgorithm(Single(digest, "ds:DigestMethod", ns).GetAttribute("Algorithm"));
        byte[] expected = Convert.FromBase64String(Single(digest, "ds:DigestValue", ns).InnerText.Trim());
        Certificate? match = known.FirstOrDefault(c => PkiAlgorithms.DigestMatches(hash, c.Encoded, expected, c.HasDstu4145Key ? c.PublicKey.Dke : null));
        report.Check("signing certificate", match is not null, match is not null
            ? $"{PkiAlgorithms.HashName(hash)} of the certificate matches the signed properties"
            : "the signed properties name a certificate that is not available");
        return match;
    }

    private static List<(string, IReadOnlyCollection<string>?)> Transforms(XmlElement reference, XmlNamespaceManager ns) =>
        reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.Cast<XmlElement>()
            .Select(t => (t.GetAttribute("Algorithm"), InclusivePrefixes(t, ns)))
            .ToList();

    private static IReadOnlyCollection<string>? InclusivePrefixes(XmlElement method, XmlNamespaceManager ns)
    {
        var list = method.SelectSingleNode("*[local-name()='InclusiveNamespaces']") as XmlElement;
        return list?.GetAttribute("PrefixList").Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// The XML-DSig processing model (XML-DSig 1.0, 4.3.3.2): a node set goes through the transforms and, if no
    /// canonicalization ends it, through inclusive C14N. Supported: enveloped-signature and the four C14N methods.
    /// </summary>
    private static byte[] ApplyTransforms(XmlNode target, List<(string Algorithm, IReadOnlyCollection<string>? Prefixes)> transforms, XmlElement signature)
    {
        XmlNode? excluded = null;
        foreach (var (algorithm, prefixes) in transforms)
        {
            if (algorithm == EnvelopedSignature)
                excluded = signature;
            else if (XmlCanonicalizer.IsSupported(algorithm))
                return XmlCanonicalizer.Canonicalize(target, algorithm, prefixes, excluded);
            else
                throw new NotSupportedException($"Transform {algorithm} is not supported.");
        }
        return XmlCanonicalizer.Canonicalize(target, XmlCanonicalizer.InclusiveC14N, null, excluded);
    }

    /// <summary>The single element whose Id (or ID, id) attribute is <paramref name="id"/>.</summary>
    private static XmlElement FindById(XmlDocument document, string id)
    {
        List<XmlElement> matches = document.GetElementsByTagName("*").Cast<XmlElement>()
            .Where(e => e.GetAttribute("Id") == id || e.GetAttribute("ID") == id || e.GetAttribute("id") == id)
            .ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new InvalidDataException($"No element with Id '{id}'."),
            _ => throw new InvalidDataException($"Several elements have Id '{id}'."),
        };
    }

    private static bool IsDescendant(XmlNode node, XmlNode ancestor)
    {
        for (XmlNode? n = node.ParentNode; n is not null; n = n.ParentNode)
        {
            if (ReferenceEquals(n, ancestor))
                return true;
        }
        return false;
    }

    private static XmlElement Single(XmlNode parent, string xpath, XmlNamespaceManager ns) =>
        parent.SelectSingleNode(xpath, ns) as XmlElement ?? throw new InvalidDataException($"{xpath} is missing.");

    private static IEnumerable<byte[]> ReadAll(XmlNode parent, string xpath, XmlNamespaceManager ns) =>
        parent.SelectNodes(xpath, ns)!.Cast<XmlElement>().Select(e => Convert.FromBase64String(e.InnerText.Trim()));
}
