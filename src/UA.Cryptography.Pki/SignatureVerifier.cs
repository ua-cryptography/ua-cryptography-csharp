using System.Xml;
using UA.Cryptography.Pki.Asic;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.Xades;
using UA.Cryptography.Pki.Xml;

namespace UA.Cryptography.Pki;

/// <summary>
/// Verifies a signed file of any supported format, recognised by its content: ASiC-S / ASiC-E (ZIP), XAdES (XML) or
/// CAdES (DER, PEM or base64).
/// </summary>
public static class SignatureVerifier
{
    /// <summary>The title of the report on an ASiC container's structure, which comes before the signatures' reports.</summary>
    public const string ContainerTitle = "container";

    /// <summary>
    /// Verifies <paramref name="signature"/>. <paramref name="detached"/> resolves the data of detached signatures: it is
    /// called with the file name a XAdES reference uses, or with null for a detached CAdES; it returns null when the data
    /// is not available.
    /// </summary>
    public static VerificationResult Verify(byte[] signature, Func<string?, byte[]?> detached, ValidationOptions options)
    {
        if (AsicContainer.LooksLikeZip(signature))
            return VerifyAsic(signature, options);
        if (XmlSafe.LooksLikeXml(signature))
        {
            XmlDocument document = XmlSafe.Load(signature);
            List<VerificationReport> reports = XadesVerifier.Verify(document, name => detached(name), options);
            var files = XadesVerifier.ExternalReferences(document).Distinct()
                .Select(n => (Name: n, Content: detached(n))).Where(f => f.Content is not null).ToDictionary(f => f.Name, f => f.Content!);
            return new VerificationResult("XAdES (XML)", reports) { SignedFiles = files };
        }
        return CadesVerifier.Verify(Pem.Decode(signature, "CMS"), detached(null), options);
    }

    private static VerificationResult VerifyAsic(byte[] container, ValidationOptions options)
    {
        var (mimeType, entries, firstAndStored) = AsicContainer.Read(container);
        var structure = new VerificationReport(ContainerTitle);
        structure.Check("mimetype", firstAndStored, firstAndStored ? $"'{mimeType}', first and stored" : "the mimetype entry must be first and uncompressed");
        List<string> data = AsicContainer.DataEntries(entries.Keys).ToList();
        var files = data.ToDictionary(n => n, n => entries[n]);
        byte[]? Resolve(string? name) => name is not null && entries.TryGetValue(name, out byte[]? content) && !name.StartsWith("META-INF/", StringComparison.Ordinal)
            ? content
            : null;

        List<string> xadesEntries = entries.Keys.Where(n => n.StartsWith("META-INF/", StringComparison.Ordinal)
            && n.Contains("signature", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)).ToList();
        List<string> cadesEntries = entries.Keys.Where(n => n.StartsWith("META-INF/", StringComparison.Ordinal)
            && n.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)).ToList();

        var reports = new List<VerificationReport>();
        string format;
        if (mimeType == AsicContainer.AsicSMimeType)
        {
            format = "ASiC-S";
            structure.Check("data", data.Count == 1, data.Count == 1 ? $"one data file '{data[0]}'" : $"{data.Count} data files; ASiC-S holds exactly one");
            byte[]? single = data.Count == 1 ? entries[data[0]] : null;
            foreach (string entry in cadesEntries)
                reports.AddRange(Titled(CadesVerifier.Verify(entries[entry], single, options).Signatures, entry));
        }
        else if (mimeType == AsicContainer.AsicEMimeType)
        {
            format = "ASiC-E";
            CheckManifest(entries, data, structure);
            if (cadesEntries.Count > 0)
                structure.Warn("signatures", "CAdES signatures in ASiC-E (ASiCManifest) are not verified");
        }
        else
        {
            format = "ZIP";
            structure.Fail("mimetype", $"'{mimeType}' is not an ASiC media type");
        }

        var covered = new HashSet<string>(StringComparer.Ordinal);
        foreach (string entry in xadesEntries)
        {
            XmlDocument document = XmlSafe.Load(entries[entry]);
            covered.UnionWith(XadesVerifier.ExternalReferences(document));
            reports.AddRange(Titled(XadesVerifier.Verify(document, n => Resolve(n), options), entry));
        }
        if (mimeType == AsicContainer.AsicSMimeType && cadesEntries.Count > 0 && data.Count == 1)
            covered.Add(data[0]);
        foreach (string file in data.Where(f => !covered.Contains(f)))
            structure.Fail($"file '{file}'", "is in the container but not covered by any signature");
        if (reports.Count == 0)
            structure.Fail("signatures", "the container holds no signature");

        return new VerificationResult(format, [structure, .. reports]) { SignedFiles = files };
    }

    private static void CheckManifest(Dictionary<string, byte[]> entries, List<string> data, VerificationReport structure)
    {
        if (!entries.TryGetValue("META-INF/manifest.xml", out byte[]? manifestBytes))
        {
            structure.Warn("manifest", "META-INF/manifest.xml is missing");
            return;
        }
        XmlDocument manifest = XmlSafe.Load(manifestBytes);
        HashSet<string> listed = manifest.GetElementsByTagName("file-entry", AsicContainer.ManifestNamespace).Cast<XmlElement>()
            .Select(e => e.GetAttribute("full-path", AsicContainer.ManifestNamespace)).ToHashSet(StringComparer.Ordinal);
        List<string> missing = data.Where(f => !listed.Contains(f)).ToList();
        if (missing.Count == 0)
            structure.Pass("manifest", $"lists all {data.Count} data files");
        else
            structure.Warn("manifest", $"does not list {string.Join(", ", missing)}");
    }

    private static IEnumerable<VerificationReport> Titled(IEnumerable<VerificationReport> reports, string entry)
    {
        foreach (VerificationReport r in reports)
        {
            r.Title = $"{r.Title} ({entry})";
            yield return r;
        }
    }
}
