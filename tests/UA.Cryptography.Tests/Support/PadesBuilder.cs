using System.Globalization;
using System.IO.Compression;
using System.Text;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>PAdES levels (ETSI EN 319 142).</summary>
public enum PadesLevel
{
    /// <summary>PAdES-B-B: the signature field with a detached CAdES signature.</summary>
    B,

    /// <summary>PAdES-B-T: + signatureTimeStampToken inside the CAdES signature.</summary>
    T,

    /// <summary>PAdES-B-LT: + Document Security Store with certificates and OCSP responses.</summary>
    LT,

    /// <summary>PAdES-B-LTA: + document time-stamp over the whole file.</summary>
    LTA,
}

/// <summary>
/// Signs a PDF the way PAdES does it (docs/signature-formats.md, section 11): the original file is never rewritten,
/// every step is an incremental update ending with its own <c>%%EOF</c> — the signature dictionary, then the DSS, then
/// the document time-stamp. Each signature's /ByteRange covers the whole file at that moment except its /Contents.
/// The PDF is minimal (no cross-reference tables) but has exactly the structure <see cref="PdfInspector"/> reads.
/// </summary>
internal static class PadesBuilder
{
    private const int NumberWidth = 10;
    private const int SignatureCapacity = 32768; // hex digits reserved for /Contents
    private const int TimeStampCapacity = 16384;

    /// <summary>A tiny unsigned PDF to sign.</summary>
    public static byte[] OriginalPdf { get; } = Encoding.Latin1.GetBytes(
        "%PDF-1.7\n" +
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
        "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
        "%%EOF\n");

    public static byte[] Sign(byte[] pdf, Hierarchy pki, PadesLevel level)
    {
        string time = DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        var options = new CadesOptions(Oids.Dstu7564_256, Enveloped: false, level >= PadesLevel.T ? CadesLevel.T : CadesLevel.B, SigningTime: false);
        byte[] signed = AppendSignature(pdf, 3,
            $"/Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:{time}Z)", SignatureCapacity,
            covered => CadesBuilder.Build(covered, pki, options));
        if (level < PadesLevel.LT)
            return signed;

        byte[] withDss = AppendDss(signed, 4, pki);
        if (level < PadesLevel.LTA)
            return withDss;

        int next = 4 + 1 + pki.ValidationCertificates.Count + DssResponses(pki).Count;
        return AppendSignature(withDss, next, "/Type /DocTimeStamp /SubFilter /ETSI.RFC3161", TimeStampCapacity,
            covered => pki.Tsa.Stamp(covered, Oids.Dstu7564_256));
    }

    /// <summary>"good" responses for the signer, its CA and the time-stamping service.</summary>
    public static IReadOnlyList<Org.BouncyCastle.Asn1.Ocsp.BasicOcspResponse> DssResponses(Hierarchy pki) =>
        [.. pki.SignerRevocationData, pki.RootOcsp.Respond(pki.Tsa.Identity.Certificate, pki.Root.Certificate)];

    /// <summary>
    /// Appends a signature dictionary as object <paramref name="number"/> with a zeroed /Contents of
    /// <paramref name="capacity"/> hex digits, then fills /ByteRange and puts <paramref name="sign"/>(covered bytes) there.
    /// </summary>
    private static byte[] AppendSignature(byte[] pdf, int number, string dictionary, int capacity, Func<byte[], byte[]> sign)
    {
        string placeholder = new('0', NumberWidth);
        string update =
            $"{number} 0 obj\n<< {dictionary} /ByteRange [0 {placeholder} {placeholder} {placeholder}] " +
            $"/Contents <{new string('0', capacity)}> >>\nendobj\n%%EOF\n";
        byte[] result = [.. pdf, .. Encoding.Latin1.GetBytes(update)];

        string text = Encoding.Latin1.GetString(result);
        int byteRange = text.LastIndexOf("/ByteRange [0 ", StringComparison.Ordinal) + "/ByteRange [0 ".Length;
        int contentsStart = text.LastIndexOf("/Contents <", StringComparison.Ordinal) + "/Contents ".Length; // at '<'
        int contentsEnd = contentsStart + capacity + 2;                                                      // after '>'
        WriteNumber(result, byteRange, contentsStart);
        WriteNumber(result, byteRange + NumberWidth + 1, contentsEnd);
        WriteNumber(result, byteRange + 2 * (NumberWidth + 1), result.Length - contentsEnd);

        string hex = Convert.ToHexString(sign(PdfInspector.Covered(result, [0, contentsStart, contentsEnd, result.Length - contentsEnd])));
        if (hex.Length > capacity)
            throw new InvalidOperationException($"The signature ({hex.Length} hex digits) does not fit into /Contents ({capacity}).");
        Encoding.ASCII.GetBytes(hex).CopyTo(result, contentsStart + 1); // the rest stays zero padding
        return result;
    }

    /// <summary>
    /// Appends the Document Security Store: a /DSS dictionary (object <paramref name="number"/>) whose /Certs and /OCSPs
    /// list Flate-compressed streams with the DER certificates and full OCSPResponse structures.
    /// </summary>
    private static byte[] AppendDss(byte[] pdf, int number, Hierarchy pki)
    {
        byte[][] certificates = pki.ValidationCertificates.Select(c => c.GetEncoded()).ToArray();
        byte[][] responses = DssResponses(pki).Select(OcspResponder.Encode).ToArray();
        int[] certificateObjects = Enumerable.Range(number + 1, certificates.Length).ToArray();
        int[] responseObjects = Enumerable.Range(number + 1 + certificates.Length, responses.Length).ToArray();

        using var update = new MemoryStream();
        Write(update, $"{number} 0 obj\n<< /Type /DSS /Certs [{References(certificateObjects)}] /OCSPs [{References(responseObjects)}] >>\nendobj\n");
        foreach ((int n, byte[] content) in certificateObjects.Zip(certificates).Concat(responseObjects.Zip(responses)))
        {
            byte[] compressed = Deflate(content);
            Write(update, $"{n} 0 obj\n<< /Length {compressed.Length} /Filter /FlateDecode >>\nstream\n");
            update.Write(compressed);
            Write(update, "\nendstream\nendobj\n");
        }
        Write(update, "%%EOF\n");
        return [.. pdf, .. update.ToArray()];
    }

    private static string References(IEnumerable<int> objects) => string.Join(" ", objects.Select(n => $"{n} 0 R"));

    private static byte[] Deflate(byte[] data)
    {
        using var buffer = new MemoryStream();
        using (var z = new ZLibStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
            z.Write(data);
        return buffer.ToArray();
    }

    private static void Write(Stream stream, string text) => stream.Write(Encoding.Latin1.GetBytes(text));

    private static void WriteNumber(byte[] bytes, int offset, int value) =>
        Encoding.ASCII.GetBytes(value.ToString(CultureInfo.InvariantCulture).PadLeft(NumberWidth, '0')).CopyTo(bytes, offset);
}
