using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// Reads the parts of a signed PDF that PAdES validation needs, with a few regular expressions: signature
/// dictionaries (/ByteRange, /Contents, /SubFilter), indirect object streams and the /DSS. Enough for the files of
/// <see cref="PadesBuilder"/> and for typical signed PDFs; a general reader also needs cross-reference streams
/// (/XRef), object streams (/ObjStm) and indirect /Length values.
/// </summary>
internal static partial class PdfInspector
{
    /// <summary>A signature dictionary: /Type, /SubFilter, the signed byte ranges and the CMS from /Contents.</summary>
    public sealed record Signature(string Type, string SubFilter, long[] ByteRange, int ContentsStart, int ContentsEnd, CmsSignedData Cms);

    // PDF syntax is ASCII; Latin-1 keeps byte offsets equal to string offsets.
    public static string Text(byte[] pdf) => Encoding.Latin1.GetString(pdf);

    public static List<Signature> ReadSignatures(byte[] pdf)
    {
        string text = Text(pdf);
        var result = new List<Signature>();
        foreach (Match m in ByteRangePattern().Matches(text))
        {
            // The enclosing object: from the preceding "obj" to the following "endobj".
            int start = text.LastIndexOf(" obj", m.Index, StringComparison.Ordinal);
            int end = text.IndexOf("endobj", m.Index, StringComparison.Ordinal);
            string dictionary = text[start..end];
            Match contents = ContentsPattern().Match(dictionary);
            string type = TypePattern().Match(dictionary).Groups[1].Value;
            string subFilter = SubFilterPattern().Match(dictionary).Groups[1].Value;

            // /Contents is zero-padded to a fixed size; the CMS is the first DER object in it.
            byte[] der = Convert.FromHexString(contents.Groups[1].Value);
            var cms = new CmsSignedData(new Asn1InputStream(der).ReadObject().GetEncoded());
            int contentsStart = start + contents.Index + contents.Value.IndexOf('<');
            int contentsEnd = start + contents.Index + contents.Length;
            long[] byteRange = m.Groups.Values.Skip(1).Select(g => long.Parse(g.Value)).ToArray();
            result.Add(new Signature(type, subFilter, byteRange, contentsStart, contentsEnd, cms));
        }
        return result;
    }

    /// <summary>The signed bytes of /ByteRange [a b c d]: [a, a + b) and [c, c + d).</summary>
    public static byte[] Covered(byte[] pdf, long[] r) =>
        [.. pdf.AsSpan((int)r[0], (int)r[1]), .. pdf.AsSpan((int)r[2], (int)r[3])];

    /// <summary>The latest version (last occurrence) of an indirect object's stream, decompressed.</summary>
    public static byte[] Stream(byte[] pdf, int number)
    {
        string text = Text(pdf);
        Match m = Regex.Matches(text, $@"(?<![0-9]){number} 0 obj\s*<<(.*?)>>\s*stream\r?\n", RegexOptions.Singleline).Last();
        string header = m.Groups[1].Value;
        int length = int.Parse(LengthPattern().Match(header).Groups[1].Value);
        byte[] data = pdf.AsSpan(m.Index + m.Length, length).ToArray();
        if (!header.Contains("/FlateDecode", StringComparison.Ordinal))
            return data;
        using var z = new ZLibStream(new MemoryStream(data), CompressionMode.Decompress);
        using var buffer = new MemoryStream();
        z.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>Object numbers listed under a key of the (latest) /DSS dictionary, e.g. /Certs [ 25 0 R 26 0 R ].</summary>
    public static int[] DssReferences(byte[] pdf, string key)
    {
        Match dss = DssPattern().Matches(Text(pdf)).Last();
        Match list = Regex.Match(dss.Groups[1].Value, $@"/{key}\s*\[([^\]]*)\]");
        return list.Success
            ? ReferencePattern().Matches(list.Groups[1].Value).Select(r => int.Parse(r.Groups[1].Value)).ToArray()
            : [];
    }

    [GeneratedRegex(@"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")]
    private static partial Regex ByteRangePattern();

    [GeneratedRegex(@"/Contents\s*<([0-9A-Fa-f]+)>")]
    private static partial Regex ContentsPattern();

    [GeneratedRegex(@"/Type\s*/(\w+)")]
    private static partial Regex TypePattern();

    [GeneratedRegex(@"/SubFilter\s*/([\w.]+)")]
    private static partial Regex SubFilterPattern();

    [GeneratedRegex(@"/Length\s+(\d+)(?!\s+\d+\s+R)")]
    private static partial Regex LengthPattern();

    [GeneratedRegex(@"/Type\s*/DSS(.*?)>>", RegexOptions.Singleline)]
    private static partial Regex DssPattern();

    [GeneratedRegex(@"(\d+)\s+0\s+R")]
    private static partial Regex ReferencePattern();
}
