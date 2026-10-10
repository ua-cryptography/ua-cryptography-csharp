using System.Text;

namespace UA.Cryptography.Pki.Asn1;

/// <summary>Accepts DER, PEM (RFC 7468) or bare base64 text and returns the DER bytes.</summary>
public static class Pem
{
    public static byte[] Decode(ReadOnlySpan<byte> data, string label)
    {
        if (data.Length > 0 && data[0] == Asn1Tag.Sequence)
            return data.ToArray();
        string text = Encoding.ASCII.GetString(data).Trim();
        string begin = $"-----BEGIN {label}-----";
        string end = $"-----END {label}-----";
        int start = text.IndexOf(begin, StringComparison.Ordinal);
        if (start >= 0)
        {
            int stop = text.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0)
                throw new InvalidDataException($"PEM block {label} is not terminated.");
            text = text[(start + begin.Length)..stop];
        }
        try
        {
            return Convert.FromBase64String(string.Concat(text.Where(c => !char.IsWhiteSpace(c))));
        }
        catch (FormatException)
        {
            throw new InvalidDataException($"The data is neither DER nor PEM ({label}).");
        }
    }

    public static string Encode(ReadOnlySpan<byte> der, string label) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n", StringComparison.Ordinal)}\n-----END {label}-----\n";
}
