using System.Globalization;
using System.Numerics;
using System.Text;

namespace UA.Cryptography.Pki.Asn1;

/// <summary>
/// One parsed ASN.1 element (tag, length, contents) over the original bytes. The reader accepts DER and the BER
/// forms met in CMS (indefinite lengths, constructed strings); <see cref="Encoded"/> is always the exact slice of the
/// input, so signed structures (TBSCertificate, signed attributes, tbsResponseData) are hashed as they were received.
/// Only low tag numbers (0–30) are supported: PKI structures use no others.
/// </summary>
public sealed class Asn1Node
{
    private const int MaxDepth = 64;
    private IReadOnlyList<Asn1Node>? _children;
    private readonly int _depth;

    private Asn1Node(byte tag, ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> content, int depth, IReadOnlyList<Asn1Node>? children)
    {
        Tag = tag;
        Encoded = encoded;
        Content = content;
        _depth = depth;
        _children = children;
    }

    /// <summary>The identifier octet: class (bits 8–7), constructed flag (bit 6) and tag number.</summary>
    public byte Tag { get; }

    /// <summary>The whole element: identifier, length and contents (for indefinite lengths, up to the end-of-contents).</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The contents octets (for an indefinite length, without the end-of-contents octets).</summary>
    public ReadOnlyMemory<byte> Content { get; }

    public bool IsConstructed => (Tag & 0x20) != 0;

    /// <summary>True for a context-specific tag [<paramref name="number"/>], primitive or constructed.</summary>
    public bool IsContext(int number) => (Tag & 0xC0) == 0x80 && (Tag & 0x1F) == number;

    /// <summary>The children of a constructed element, parsed on first access.</summary>
    public IReadOnlyList<Asn1Node> Children
    {
        get
        {
            if (_children is not null)
                return _children;
            if (!IsConstructed)
                throw new InvalidDataException($"ASN.1 element with tag 0x{Tag:X2} is primitive and has no children.");
            _children = ParseAll(Content, _depth + 1);
            return _children;
        }
    }

    public int Count => Children.Count;

    public Asn1Node this[int index] => index < Count
        ? Children[index]
        : throw new InvalidDataException($"ASN.1 element with tag 0x{Tag:X2} has {Count} children, element {index} is missing.");

    /// <summary>Parses exactly one element; trailing bytes are an error.</summary>
    public static Asn1Node Parse(ReadOnlyMemory<byte> data)
    {
        Asn1Node node = ReadFirst(data, out int length);
        if (length != data.Length)
            throw new InvalidDataException($"Unexpected {data.Length - length} bytes after the ASN.1 element.");
        return node;
    }

    /// <summary>Parses the first element of <paramref name="data"/> and returns its encoded length.</summary>
    public static Asn1Node ReadFirst(ReadOnlyMemory<byte> data, out int length) => Read(data, 0, 0, out length);

    /// <summary>True when <paramref name="data"/> is exactly one well-formed element.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> data, out Asn1Node? node)
    {
        try
        {
            node = Parse(data);
            return true;
        }
        catch (InvalidDataException)
        {
            node = null;
            return false;
        }
    }

    private static List<Asn1Node> ParseAll(ReadOnlyMemory<byte> data, int depth)
    {
        var result = new List<Asn1Node>();
        int offset = 0;
        while (offset < data.Length)
        {
            result.Add(Read(data, offset, depth, out int length));
            offset += length;
        }
        return result;
    }

    private static Asn1Node Read(ReadOnlyMemory<byte> data, int offset, int depth, out int length)
    {
        if (depth > MaxDepth)
            throw new InvalidDataException("ASN.1 nesting is too deep.");
        ReadOnlySpan<byte> span = data.Span;
        if (offset + 2 > span.Length)
            throw new InvalidDataException("Truncated ASN.1 element.");
        byte tag = span[offset];
        if ((tag & 0x1F) == 0x1F)
            throw new InvalidDataException("High-tag-number ASN.1 forms are not supported.");
        int position = offset + 1;
        int first = span[position++];

        if (first == 0x80)
        {
            // Indefinite length (BER): children up to the end-of-contents octets 00 00.
            if ((tag & 0x20) == 0)
                throw new InvalidDataException("A primitive ASN.1 element cannot have an indefinite length.");
            int contentStart = position;
            var children = new List<Asn1Node>();
            while (true)
            {
                if (position + 2 > span.Length)
                    throw new InvalidDataException("Missing end-of-contents octets.");
                if (span[position] == 0 && span[position + 1] == 0)
                    break;
                children.Add(Read(data, position, depth + 1, out int childLength));
                position += childLength;
            }
            length = position + 2 - offset;
            return new Asn1Node(tag, data.Slice(offset, length), data[contentStart..position], depth, children);
        }

        int contentLength;
        if (first < 0x80)
        {
            contentLength = first;
        }
        else
        {
            int octets = first & 0x7F;
            if (octets > 4 || position + octets > span.Length)
                throw new InvalidDataException("Invalid ASN.1 length.");
            long value = 0;
            for (int i = 0; i < octets; i++)
                value = (value << 8) | span[position++];
            if (value > int.MaxValue)
                throw new InvalidDataException("ASN.1 length is too large.");
            contentLength = (int)value;
        }
        if (contentLength > span.Length - position)
            throw new InvalidDataException("ASN.1 length exceeds the data.");
        length = position + contentLength - offset;
        return new Asn1Node(tag, data.Slice(offset, length), data.Slice(position, contentLength), depth, null);
    }

    // ---- Typed accessors -------------------------------------------------------------------------------------

    /// <summary>Throws unless the element has the given identifier octet.</summary>
    public Asn1Node Expect(byte tag) => Tag == tag
        ? this
        : throw new InvalidDataException($"Expected ASN.1 tag 0x{tag:X2}, found 0x{Tag:X2}.");

    public bool Is(byte tag) => Tag == tag;

    public BigInteger GetInteger()
    {
        Expect(Asn1Tag.Integer);
        if (Content.Length == 0)
            throw new InvalidDataException("Empty INTEGER.");
        return new BigInteger(Content.Span, isUnsigned: false, isBigEndian: true);
    }

    public int GetInt32()
    {
        BigInteger value = GetInteger();
        return value >= int.MinValue && value <= int.MaxValue
            ? (int)value
            : throw new InvalidDataException("INTEGER does not fit into 32 bits.");
    }

    public bool GetBoolean()
    {
        Expect(Asn1Tag.Boolean);
        return Content.Length == 1 ? Content.Span[0] != 0 : throw new InvalidDataException("Invalid BOOLEAN.");
    }

    public string GetOid()
    {
        Expect(Asn1Tag.ObjectIdentifier);
        return Der.DecodeOid(Content.Span);
    }

    /// <summary>The contents of an OCTET STRING, primitive or constructed (BER), with any implicit tag.</summary>
    public byte[] GetOctetString()
    {
        if (!IsConstructed)
            return Content.ToArray();
        using var buffer = new MemoryStream();
        foreach (Asn1Node segment in Children)
            buffer.Write(segment.GetOctetString());
        return buffer.ToArray();
    }

    /// <summary>The bytes of a BIT STRING with no unused bits (keys and signatures always are).</summary>
    public byte[] GetBitString()
    {
        Expect(Asn1Tag.BitString);
        ReadOnlySpan<byte> c = Content.Span;
        if (c.Length == 0 || c[0] > 7)
            throw new InvalidDataException("Invalid BIT STRING.");
        return c[1..].ToArray();
    }

    /// <summary>A named BIT STRING (such as keyUsage) as an integer: bit 0 of the ASN.1 value is bit 0 of the result.</summary>
    public int GetNamedBits()
    {
        Expect(Asn1Tag.BitString);
        ReadOnlySpan<byte> c = Content.Span;
        int result = 0;
        for (int i = 1; i < c.Length && i <= 4; i++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                if ((c[i] & (0x80 >> bit)) != 0)
                    result |= 1 << ((i - 1) * 8 + bit);
            }
        }
        return result;
    }

    /// <summary>Any ASN.1 character string type as text.</summary>
    public string GetString() => Tag switch
    {
        Asn1Tag.Utf8String => Encoding.UTF8.GetString(Content.Span),
        Asn1Tag.BmpString => Encoding.BigEndianUnicode.GetString(Content.Span),
        Asn1Tag.UniversalString => new UTF32Encoding(bigEndian: true, byteOrderMark: false).GetString(Content.Span),
        Asn1Tag.PrintableString or Asn1Tag.Ia5String or Asn1Tag.NumericString or Asn1Tag.VisibleString or Asn1Tag.TeletexString
            => Encoding.Latin1.GetString(Content.Span),
        _ => throw new InvalidDataException($"ASN.1 tag 0x{Tag:X2} is not a character string."),
    };

    /// <summary>A UTCTime or GeneralizedTime value.</summary>
    public DateTimeOffset GetTime()
    {
        string text = Encoding.ASCII.GetString(Content.Span);
        if (Tag == Asn1Tag.UtcTime)
        {
            DateTimeOffset t = ParseTime(text, "yyMMddHHmmss", "yyMMddHHmm");
            // X.509 (RFC 5280, 4.1.2.5.1): YY >= 50 is 19YY, YY < 50 is 20YY.
            int year = int.Parse(text[..2], CultureInfo.InvariantCulture);
            int century = year >= 50 ? 1900 : 2000;
            return t.AddYears(century + year - t.Year);
        }
        if (Tag == Asn1Tag.GeneralizedTime)
            return ParseTime(text, "yyyyMMddHHmmss", "yyyyMMddHHmmss.FFFFFFF", "yyyyMMddHHmm");
        throw new InvalidDataException($"ASN.1 tag 0x{Tag:X2} is not a time.");
    }

    private static DateTimeOffset ParseTime(string text, params string[] formats)
    {
        string body = text;
        TimeSpan offset = TimeSpan.Zero;
        if (body.EndsWith('Z'))
        {
            body = body[..^1];
        }
        else if (body.Length > 5 && (body[^5] == '+' || body[^5] == '-'))
        {
            int sign = body[^5] == '-' ? -1 : 1;
            offset = sign * new TimeSpan(int.Parse(body[^4..^2], CultureInfo.InvariantCulture), int.Parse(body[^2..], CultureInfo.InvariantCulture), 0);
            body = body[..^5];
        }
        body = body.Replace(',', '.');
        if (!DateTime.TryParseExact(body, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime local))
            throw new InvalidDataException($"Invalid ASN.1 time '{text}'.");
        return new DateTimeOffset(local, offset).ToUniversalTime();
    }

    public override string ToString() => $"ASN.1 0x{Tag:X2}, {Content.Length} bytes";
}
