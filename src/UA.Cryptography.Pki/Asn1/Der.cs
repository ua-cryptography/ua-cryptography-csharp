using System.Globalization;
using System.Numerics;
using System.Text;

namespace UA.Cryptography.Pki.Asn1;

/// <summary>
/// DER encoder (X.690, section 10): every function returns one complete element, and constructed values are built
/// by nesting calls. Kept deliberately small so that it ports line by line to other languages.
/// </summary>
public static class Der
{
    /// <summary>An element with the given identifier octet and contents.</summary>
    public static byte[] Encode(byte tag, ReadOnlySpan<byte> content)
    {
        int length = content.Length;
        int lengthOctets = length < 0x80 ? 0 : length <= 0xFF ? 1 : length <= 0xFFFF ? 2 : length <= 0xFFFFFF ? 3 : 4;
        var result = new byte[2 + lengthOctets + length];
        result[0] = tag;
        if (lengthOctets == 0)
        {
            result[1] = (byte)length;
        }
        else
        {
            result[1] = (byte)(0x80 | lengthOctets);
            for (int i = 0; i < lengthOctets; i++)
                result[2 + i] = (byte)(length >> (8 * (lengthOctets - 1 - i)));
        }
        content.CopyTo(result.AsSpan(2 + lengthOctets));
        return result;
    }

    /// <summary>Shorthand for <see cref="Asn1Node.Parse"/>.</summary>
    public static Asn1Node Parse(ReadOnlyMemory<byte> data) => Asn1Node.Parse(data);

    public static byte[] Concat(IEnumerable<byte[]> items)
    {
        using var buffer = new MemoryStream();
        foreach (byte[] item in items)
            buffer.Write(item);
        return buffer.ToArray();
    }

    public static byte[] Sequence(params byte[][] items) => Encode(Asn1Tag.Sequence, Concat(items));

    public static byte[] Sequence(IEnumerable<byte[]> items) => Encode(Asn1Tag.Sequence, Concat(items));

    /// <summary>A DER SET OF: the encodings are sorted as octet strings (X.690, 11.6).</summary>
    public static byte[] SetOf(IEnumerable<byte[]> items)
    {
        List<byte[]> sorted = items.ToList();
        sorted.Sort(CompareEncodings);
        return Encode(Asn1Tag.Set, Concat(sorted));
    }

    public static byte[] SetOf(params byte[][] items) => SetOf((IEnumerable<byte[]>)items);

    // Shorter encodings are compared as if padded with zero octets at the end.
    private static int CompareEncodings(byte[] a, byte[] b)
    {
        int n = System.Math.Max(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            int x = i < a.Length ? a[i] : 0;
            int y = i < b.Length ? b[i] : 0;
            if (x != y)
                return x - y;
        }
        return a.Length - b.Length;
    }

    public static byte[] Boolean(bool value) => Encode(Asn1Tag.Boolean, [value ? (byte)0xFF : (byte)0x00]);

    public static byte[] Null() => [Asn1Tag.Null, 0];

    /// <summary>An INTEGER in the shortest two's complement form.</summary>
    public static byte[] Integer(BigInteger value) => Encode(Asn1Tag.Integer, value.ToByteArray(isUnsigned: false, isBigEndian: true));

    public static byte[] Integer(long value) => Integer(new BigInteger(value));

    public static byte[] OctetString(ReadOnlySpan<byte> value) => Encode(Asn1Tag.OctetString, value);

    /// <summary>A BIT STRING whose length is a whole number of octets.</summary>
    public static byte[] BitString(ReadOnlySpan<byte> value)
    {
        var content = new byte[value.Length + 1];
        value.CopyTo(content.AsSpan(1));
        return Encode(Asn1Tag.BitString, content);
    }

    /// <summary>A named BIT STRING (X.690, 11.2.2): bit i of <paramref name="bits"/> is ASN.1 bit i; trailing zeros are removed.</summary>
    public static byte[] NamedBits(int bits)
    {
        if (bits == 0)
            return Encode(Asn1Tag.BitString, [0]);
        int highest = 31 - BitOperations.LeadingZeroCount((uint)bits);
        int octets = highest / 8 + 1;
        var content = new byte[octets + 1];
        content[0] = (byte)(7 - highest % 8);
        for (int i = 0; i <= highest; i++)
        {
            if ((bits & (1 << i)) != 0)
                content[1 + i / 8] |= (byte)(0x80 >> (i % 8));
        }
        return Encode(Asn1Tag.BitString, content);
    }

    public static byte[] Utf8String(string value) => Encode(Asn1Tag.Utf8String, Encoding.UTF8.GetBytes(value));

    public static byte[] PrintableString(string value) => Encode(Asn1Tag.PrintableString, Encoding.ASCII.GetBytes(value));

    public static byte[] Ia5String(string value) => Encode(Asn1Tag.Ia5String, Encoding.ASCII.GetBytes(value));

    public static byte[] UtcTime(DateTimeOffset time) =>
        Encode(Asn1Tag.UtcTime, Encoding.ASCII.GetBytes(time.UtcDateTime.ToString("yyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"));

    public static byte[] GeneralizedTime(DateTimeOffset time) =>
        Encode(Asn1Tag.GeneralizedTime, Encoding.ASCII.GetBytes(time.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"));

    /// <summary>X.509 Time (RFC 5280, 4.1.2.5): UTCTime for 1950–2049, GeneralizedTime otherwise.</summary>
    public static byte[] Time(DateTimeOffset time) =>
        time.UtcDateTime.Year is >= 1950 and < 2050 ? UtcTime(time) : GeneralizedTime(time);

    public static byte[] ObjectIdentifier(string oid) => Encode(Asn1Tag.ObjectIdentifier, EncodeOid(oid));

    /// <summary>AlgorithmIdentifier with absent parameters, as the Ukrainian PKI writes its own algorithms.</summary>
    public static byte[] AlgorithmIdentifier(string oid) => Sequence(ObjectIdentifier(oid));

    /// <summary>[n] EXPLICIT: a constructed context tag around a complete element.</summary>
    public static byte[] Explicit(int number, byte[] inner) => Encode(Asn1Tag.ContextConstructed(number), inner);

    /// <summary>[n] IMPLICIT: the identifier of <paramref name="encoded"/> is replaced, the constructed flag is kept.</summary>
    public static byte[] Implicit(int number, byte[] encoded)
    {
        byte[] result = (byte[])encoded.Clone();
        result[0] = (byte)(0x80 | (encoded[0] & 0x20) | number);
        return result;
    }

    // ---- Object identifiers (X.690, 8.19) ---------------------------------------------------------------------

    public static byte[] EncodeOid(string oid)
    {
        string[] parts = oid.Split('.');
        if (parts.Length < 2)
            throw new ArgumentException($"Invalid object identifier '{oid}'.", nameof(oid));
        var arcs = parts.Select(p => BigInteger.Parse(p, NumberStyles.None, CultureInfo.InvariantCulture)).ToList();
        if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40))
            throw new ArgumentException($"Invalid object identifier '{oid}'.", nameof(oid));

        var result = new List<byte>();
        WriteBase128(result, arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.Count; i++)
            WriteBase128(result, arcs[i]);
        return result.ToArray();
    }

    private static void WriteBase128(List<byte> output, BigInteger value)
    {
        var groups = new Stack<byte>();
        groups.Push((byte)(value & 0x7F));
        value >>= 7;
        while (value > 0)
        {
            groups.Push((byte)(0x80 | (byte)(value & 0x7F)));
            value >>= 7;
        }
        output.AddRange(groups);
    }

    public static string DecodeOid(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0 || (content[^1] & 0x80) != 0)
            throw new InvalidDataException("Invalid OBJECT IDENTIFIER.");
        var arcs = new List<BigInteger>();
        BigInteger value = 0;
        bool first = true;
        foreach (byte b in content)
        {
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) != 0)
                continue;
            if (first)
            {
                int top = value < 40 ? 0 : value < 80 ? 1 : 2;
                arcs.Add(top);
                arcs.Add(value - 40 * top);
                first = false;
            }
            else
            {
                arcs.Add(value);
            }
            value = 0;
        }
        return string.Join('.', arcs.Select(a => a.ToString(CultureInfo.InvariantCulture)));
    }
}
