using System.Text;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.X509;

/// <summary>
/// An X.500 Name (RFC 5280, 4.1.2.4): a sequence of relative distinguished names. Two names are equal when their DER
/// encodings are, or else when their attributes match after trimming and ignoring case (RFC 5280, 7.1, simplified).
/// </summary>
public sealed class DistinguishedName : IEquatable<DistinguishedName>
{
    private static readonly (string Key, string Oid)[] Keys =
    [
        ("CN", Oids.CommonName), ("SN", Oids.Surname), ("SERIALNUMBER", Oids.SerialNumber), ("C", Oids.Country),
        ("L", Oids.Locality), ("ST", Oids.State), ("STREET", Oids.Street), ("O", Oids.Organization),
        ("OU", Oids.OrganizationalUnit), ("T", Oids.Title), ("G", Oids.GivenName),
        ("ORGANIZATIONIDENTIFIER", Oids.OrganizationIdentifier), ("E", Oids.EmailAddress),
    ];

    private DistinguishedName(byte[] encoded, IReadOnlyList<(string Oid, string Value)> attributes)
    {
        Encoded = encoded;
        Attributes = attributes;
    }

    /// <summary>The DER encoding, exactly as found in the certificate.</summary>
    public byte[] Encoded { get; }

    /// <summary>All attributes in the order of encoding (one RDN may hold several).</summary>
    public IReadOnlyList<(string Oid, string Value)> Attributes { get; }

    /// <summary>The first value of an attribute type, e.g. <see cref="Oids.CommonName"/>.</summary>
    public string? Get(string oid) => Attributes.FirstOrDefault(a => a.Oid == oid).Value;

    public static DistinguishedName FromAsn1(Asn1Node name)
    {
        name.Expect(Asn1Tag.Sequence);
        var attributes = new List<(string, string)>();
        foreach (Asn1Node rdn in name.Children)
        {
            foreach (Asn1Node attribute in rdn.Expect(Asn1Tag.Set).Children)
            {
                Asn1Node value = attribute[1];
                string text;
                try
                {
                    text = value.GetString();
                }
                catch (InvalidDataException)
                {
                    text = "#" + Convert.ToHexString(value.Encoded.Span);
                }
                attributes.Add((attribute[0].GetOid(), text));
            }
        }
        return new DistinguishedName(name.Encoded.ToArray(), attributes);
    }

    /// <summary>
    /// Parses "CN=Name, O=Organization, C=UA" (RFC 4514 keys plus OIDs; a comma inside a value is written "\,"). The RDNs
    /// are encoded in the order written. C and SERIALNUMBER become PrintableString, E an IA5String, the rest UTF8String.
    /// </summary>
    public static DistinguishedName Parse(string text)
    {
        var attributes = new List<(string Oid, string Value)>();
        foreach (string part in SplitUnescaped(text))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0)
                throw new FormatException($"Invalid distinguished name component '{part}'.");
            string key = part[..eq].Trim();
            string value = part[(eq + 1)..].Trim();
            string oid = Keys.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Oid
                ?? (key.Contains('.') ? key : throw new FormatException($"Unknown attribute type '{key}'."));
            attributes.Add((oid, value));
        }
        if (attributes.Count == 0)
            throw new FormatException("The distinguished name is empty.");

        byte[] encoded = Der.Sequence(attributes.Select(a => Der.SetOf(Der.Sequence(Der.ObjectIdentifier(a.Oid), EncodeValue(a.Oid, a.Value)))));
        return new DistinguishedName(encoded, attributes);
    }

    private static byte[] EncodeValue(string oid, string value) => oid switch
    {
        Oids.Country or Oids.SerialNumber => Der.PrintableString(value),
        Oids.EmailAddress => Der.Ia5String(value),
        _ => Der.Utf8String(value),
    };

    private static List<string> SplitUnescaped(string text)
    {
        var parts = new List<string>();
        var current = new StringBuilder();
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\\' && i + 1 < text.Length)
            {
                current.Append(text[++i]);
            }
            else if (c == ',' || c == ';')
            {
                parts.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        if (current.ToString().Trim().Length > 0)
            parts.Add(current.ToString());
        return parts;
    }

    public bool Equals(DistinguishedName? other)
    {
        if (other is null)
            return false;
        if (Encoded.AsSpan().SequenceEqual(other.Encoded))
            return true;
        return Attributes.Count == other.Attributes.Count
            && Attributes.Zip(other.Attributes).All(p => p.First.Oid == p.Second.Oid
                && string.Equals(Normalize(p.First.Value), Normalize(p.Second.Value), StringComparison.OrdinalIgnoreCase));
    }

    private static string Normalize(string value) => string.Join(' ', value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    public override bool Equals(object? obj) => obj is DistinguishedName n && Equals(n);

    public override int GetHashCode() => Attributes.Count;

    public override string ToString() => string.Join(", ", Attributes.Select(a =>
        $"{Keys.FirstOrDefault(k => k.Oid == a.Oid).Key ?? a.Oid}={a.Value.Replace(",", "\\,", StringComparison.Ordinal)}"));
}
