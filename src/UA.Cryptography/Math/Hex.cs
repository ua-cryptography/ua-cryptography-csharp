using System.Globalization;
using System.Numerics;
using System.Text;

namespace UA.Cryptography.Math;

/// <summary>Hex helpers tolerant to the formatting used in the text of the standard.</summary>
public static class Hex
{
    /// <summary>
    /// Parses a big-endian hex string into a non-negative integer. Whitespace, line breaks,
    /// the '/' line-continuation mark of the standard's tables and a leading "0x" are ignored.
    /// </summary>
    public static BigInteger ToBigInteger(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var sb = new StringBuilder(hex.Length + 1);
        string s = hex.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s.Substring(2);
        foreach (char ch in s)
        {
            if (char.IsWhiteSpace(ch) || ch == '/')
                continue;
            if (!Uri.IsHexDigit(ch))
                throw new FormatException($"Invalid hex character '{ch}'.");
            sb.Append(ch);
        }
        if (sb.Length == 0)
            throw new FormatException("Empty hex string.");
        sb.Insert(0, '0'); // keep the value non-negative
        return BigInteger.Parse(sb.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }

    /// <summary>Formats a non-negative integer as upper-case hex without leading zeros ("0" for zero).</summary>
    public static string FromBigInteger(BigInteger value)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(value));
        if (value.IsZero)
            return "0";
        string s = value.ToString("X", CultureInfo.InvariantCulture).TrimStart('0');
        return s.Length == 0 ? "0" : s;
    }

    /// <summary>Formats a non-negative integer as upper-case hex left-padded with zeros to <paramref name="digits"/> characters.</summary>
    public static string FromBigInteger(BigInteger value, int digits) => FromBigInteger(value).PadLeft(digits, '0');

    public static byte[] ToBytes(string hex)
    {
        string s = new string(hex.Where(c => !char.IsWhiteSpace(c)).ToArray());
        return Convert.FromHexString(s);
    }
}
