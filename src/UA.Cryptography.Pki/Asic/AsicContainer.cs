using System.IO.Compression;
using System.Text;
using System.Xml;
using UA.Cryptography.Pki.Xades;
using UA.Cryptography.Pki.Xml;

namespace UA.Cryptography.Pki.Asic;

/// <summary>
/// Associated Signature Containers (ETSI EN 319 162): ZIP archives whose first entry, stored uncompressed, is the media
/// type. ASiC-S holds one data file and META-INF/signature.p7s (a detached CAdES); ASiC-E holds data files,
/// META-INF/manifest.xml and META-INF/signatures*.xml with XAdES signatures (docs/signature-formats.md, sections 8 and 10).
/// </summary>
public static class AsicContainer
{
    public const string AsicSMimeType = "application/vnd.etsi.asic-s+zip";
    public const string AsicEMimeType = "application/vnd.etsi.asic-e+zip";
    public const string AsicSSignatureEntry = "META-INF/signature.p7s";
    public const string XadesSignaturesNamespace = "http://uri.etsi.org/02918/v1.2.1#";
    public const string ManifestNamespace = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

    /// <summary>An ASiC-S container with one data file and its detached CAdES signature.</summary>
    public static byte[] CreateAsicS(string dataName, byte[] data, byte[] detachedCades) => Zip(AsicSMimeType,
    [
        (dataName, data),
        (AsicSSignatureEntry, detachedCades),
    ]);

    /// <summary>
    /// An ASiC-E container: the data files, the manifest and the XAdES signature wrapped into asic:XAdESSignatures
    /// (exclusive canonicalization ignores the new root, so the signature stays valid).
    /// </summary>
    public static byte[] CreateAsicE(IReadOnlyList<SignedFile> files, XmlDocument signature)
    {
        var container = new XmlDocument { PreserveWhitespace = true };
        container.AppendChild(container.CreateXmlDeclaration("1.0", "UTF-8", null));
        XmlElement root = container.CreateElement("asic", "XAdESSignatures", XadesSignaturesNamespace);
        root.SetAttribute("xmlns:ds", XadesSigner.Ds);
        container.AppendChild(root);
        root.AppendChild(container.ImportNode(signature.DocumentElement!, deep: true));

        var manifest = new StringBuilder();
        manifest.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        manifest.Append($"<manifest:manifest xmlns:manifest=\"{ManifestNamespace}\">");
        manifest.Append($"<manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"{AsicEMimeType}\"/>");
        foreach (SignedFile file in files)
            manifest.Append($"<manifest:file-entry manifest:full-path=\"{SecurityElementEscape(file.Name)}\" manifest:media-type=\"{MimeTypes.Of(file.Name)}\"/>");
        manifest.Append("</manifest:manifest>");

        return Zip(AsicEMimeType,
        [
            .. files.Select(f => (f.Name, f.Content)),
            ("META-INF/manifest.xml", Encoding.UTF8.GetBytes(manifest.ToString())),
            ("META-INF/signatures001.xml", XmlSafe.Save(container)),
        ]);
    }

    private static string SecurityElementEscape(string s) =>
        s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
         .Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);

    private static byte[] Zip(string mimeType, IEnumerable<(string Name, byte[] Content)> entries)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry mimetype = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (Stream s = mimetype.Open())
                s.Write(Encoding.ASCII.GetBytes(mimeType));
            foreach ((string name, byte[] content) in entries)
            {
                if (name == "mimetype" || name.Contains("..", StringComparison.Ordinal) || name.StartsWith('/'))
                    throw new ArgumentException($"Invalid entry name '{name}'.", nameof(entries));
                ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.Optimal);
                using Stream s = entry.Open();
                s.Write(content);
            }
        }
        return buffer.ToArray();
    }

    /// <summary>True when the data starts like a ZIP archive.</summary>
    public static bool LooksLikeZip(ReadOnlySpan<byte> data) => data.Length > 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4;

    /// <summary>The entries of a container and its media type (null when the mimetype entry is missing).</summary>
    public static (string? MimeType, Dictionary<string, byte[]> Entries, bool MimeTypeFirstAndStored) Read(byte[] container)
    {
        using var zip = new ZipArchive(new MemoryStream(container), ZipArchiveMode.Read);
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        long total = 0;
        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            if (entry.FullName.EndsWith('/'))
                continue;
            total += entry.Length;
            if (total > 1L << 31)
                throw new InvalidDataException("The container is too large when unpacked.");
            using Stream s = entry.Open();
            using var b = new MemoryStream();
            s.CopyTo(b);
            entries[entry.FullName] = b.ToArray();
        }
        bool firstAndStored = zip.Entries.Count > 0 && zip.Entries[0].FullName == "mimetype" && zip.Entries[0].Length == zip.Entries[0].CompressedLength;
        string? mimeType = entries.TryGetValue("mimetype", out byte[]? m) ? Encoding.ASCII.GetString(m).Trim() : null;
        return (mimeType, entries, firstAndStored);
    }

    /// <summary>Data entries: everything except mimetype and META-INF/.</summary>
    public static IEnumerable<string> DataEntries(IEnumerable<string> names) =>
        names.Where(n => n != "mimetype" && !n.StartsWith("META-INF/", StringComparison.Ordinal));
}
