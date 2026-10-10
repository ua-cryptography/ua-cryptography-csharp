namespace UA.Cryptography.Pki.Asn1;

/// <summary>Identifier octets of the universal ASN.1 types used by PKI structures (X.680, 8.4).</summary>
public static class Asn1Tag
{
    public const byte Boolean = 0x01;
    public const byte Integer = 0x02;
    public const byte BitString = 0x03;
    public const byte OctetString = 0x04;
    public const byte Null = 0x05;
    public const byte ObjectIdentifier = 0x06;
    public const byte Enumerated = 0x0A;
    public const byte Utf8String = 0x0C;
    public const byte NumericString = 0x12;
    public const byte PrintableString = 0x13;
    public const byte TeletexString = 0x14;
    public const byte Ia5String = 0x16;
    public const byte UtcTime = 0x17;
    public const byte GeneralizedTime = 0x18;
    public const byte VisibleString = 0x1A;
    public const byte UniversalString = 0x1C;
    public const byte BmpString = 0x1E;
    public const byte Sequence = 0x30;
    public const byte Set = 0x31;

    /// <summary>Context-specific constructed tag [n] (EXPLICIT tagging, or IMPLICIT over a constructed type).</summary>
    public static byte ContextConstructed(int number) => (byte)(0xA0 | number);

    /// <summary>Context-specific primitive tag [n] (IMPLICIT over a primitive type).</summary>
    public static byte ContextPrimitive(int number) => (byte)(0x80 | number);
}
