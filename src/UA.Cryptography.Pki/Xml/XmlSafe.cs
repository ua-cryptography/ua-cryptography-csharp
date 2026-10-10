using System.Text;
using System.Xml;

namespace UA.Cryptography.Pki.Xml;

/// <summary>
/// Loads and saves XML for signatures: no DTDs and no external resources (no XXE), whitespace preserved, line ends and
/// attribute values normalized by the XML parser as the canonicalization data model expects.
/// </summary>
public static class XmlSafe
{
    public static XmlDocument Load(byte[] data)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreWhitespace = false,
            IgnoreComments = false,
            IgnoreProcessingInstructions = false,
        };
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using var reader = XmlReader.Create(new MemoryStream(data), settings);
        document.Load(reader);
        return document;
    }

    /// <summary>UTF-8 without a byte order mark, with an XML declaration, not indented.</summary>
    public static byte[] Save(XmlDocument document)
    {
        var settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false, OmitXmlDeclaration = false };
        using var buffer = new MemoryStream();
        using (var writer = XmlWriter.Create(buffer, settings))
            document.Save(writer);
        return buffer.ToArray();
    }

    /// <summary>True when the data looks like XML (after a byte order mark and whitespace).</summary>
    public static bool LooksLikeXml(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
            data = data[3..];
        foreach (byte b in data)
        {
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
                continue;
            return b == (byte)'<';
        }
        return false;
    }
}
